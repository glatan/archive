//! Brotli decoding.
//!
//! Current implementation supports empty streams, metadata blocks,
//! uncompressed metablocks, compressed metablocks including multi-block-type
//! literal switching, and the context-map parsing needed for those paths.

use alloc::vec;
use alloc::vec::Vec;

use super::dictionary;
use super::huffman;
use crate::error::Error;
use crate::util::bitreader::BitReader;

/// Decode a Brotli stream into memory.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reader = BitReader::new(input);
    let window_bits = parse_window_bits(&mut reader)?;
    let window_size = 1usize
        .checked_shl(window_bits.into())
        .ok_or(Error::InvalidData("brotli: invalid window bits"))?
        .checked_sub(16)
        .ok_or(Error::InvalidData("brotli: invalid window size"))?;
    let mut output = Vec::new();
    let mut recent_distances = RecentDistances::new();

    loop {
        match parse_metablock_header(&mut reader)? {
            MetablockHeader::LastEmpty => break,
            MetablockHeader::Metadata { skip_len } => {
                reader.align_to_byte_if_zero()?;
                reader.read_bytes(skip_len)?;
            }
            MetablockHeader::Uncompressed { is_last, len } => {
                // RFC 7932 §9.2: an uncompressed meta-block cannot be the
                // last meta-block.  The header parser structurally prevents
                // this combination, but reject it explicitly for safety.
                if is_last {
                    return Err(Error::InvalidData(
                        "brotli: uncompressed meta-block cannot be the last meta-block",
                    ));
                }
                reader.align_to_byte_if_zero()?;
                let data = reader.read_bytes(len)?;
                output.extend_from_slice(data);
            }
            MetablockHeader::Compressed { is_last, len } => {
                let header = parse_compressed_metablock_info(&mut reader)?;
                decode_compressed_metablock(
                    &mut reader,
                    &header,
                    &mut output,
                    len,
                    is_last,
                    window_size,
                    &mut recent_distances,
                )?;
                if is_last {
                    // RFC 7932 §9.3: unused bits in the last byte
                    // must be zero.
                    reader.align_to_byte_if_zero()?;
                    break;
                }
            }
        }
    }

    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetablockHeader {
    LastEmpty,
    Metadata { skip_len: usize },
    Uncompressed { is_last: bool, len: usize },
    Compressed { is_last: bool, len: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompressedMetablockInfo {
    nbltypes_l: usize,
    nbltypes_i: usize,
    nbltypes_d: usize,
    literal_block_types: BlockTypeInfo,
    insert_copy_block_types: BlockTypeInfo,
    distance_block_types: BlockTypeInfo,
    npostfix: u8,
    ndirect: usize,
    context_modes: Vec<u8>,
    ntrees_l: usize,
    ntrees_d: usize,
    literal_context_map: Vec<u8>,
    distance_context_map: Vec<u8>,
    literal_trees: Vec<huffman::HuffmanTable>,
    insert_copy_trees: Vec<huffman::HuffmanTable>,
    distance_trees: Vec<huffman::HuffmanTable>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Command {
    insert_len: usize,
    copy_len: usize,
    distance_context: usize,
    distance_code: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecentDistances {
    ring: [usize; 4],
    index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockTypeInfo {
    num_types: usize,
    type_tree: Option<huffman::HuffmanTable>,
    len_tree: Option<huffman::HuffmanTable>,
    initial_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockTypeState {
    ring: [usize; 2],
    block_type: usize,
    remaining: usize,
}

const INSERT_LENGTH_EXTRA_BITS: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];
const COPY_LENGTH_EXTRA_BITS: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
];
const INSERT_LENGTH_OFFSETS: [usize; 24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210,
    22594,
];
const COPY_LENGTH_OFFSETS: [usize; 24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
];
const COMMAND_CELL_POS: [usize; 11] = [0, 1, 0, 1, 8, 9, 2, 16, 10, 17, 18];
const BLOCK_LENGTH_PREFIX_OFFSETS: [usize; 26] = [
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265,
    2289, 4337, 8433, 16625,
];
const BLOCK_LENGTH_PREFIX_EXTRA_BITS: [u8; 26] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
];

impl RecentDistances {
    const fn new() -> Self {
        Self {
            ring: [16, 15, 11, 4],
            index: 0,
        }
    }

    const fn last(&self) -> usize {
        self.ring[self.index.wrapping_sub(1) & 3]
    }

    const fn push(&mut self, distance: usize) {
        self.ring[self.index & 3] = distance;
        self.index = self.index.wrapping_add(1);
    }

    fn resolve_short_code(&self, code: usize) -> Result<usize, Error> {
        if code <= 3 {
            let offset = code as isize - 3;
            return Ok(self.ring[self.index.wrapping_sub_signed(offset) & 3]);
        }

        let (base, index_delta) = if code < 10 {
            (code - 4, 3usize)
        } else {
            (code - 10, 2usize)
        };
        let delta = (((0x605142u32 >> (4 * base)) & 0xF) as isize) - 3;
        let distance = self.ring[(self.index + index_delta) & 3] as isize + delta;
        if distance <= 0 {
            return Err(Error::InvalidData("brotli: invalid backward distance"));
        }
        usize::try_from(distance)
            .map_err(|_| Error::InvalidData("brotli: invalid backward distance"))
    }
}

impl BlockTypeInfo {
    const fn single() -> Self {
        Self {
            num_types: 1,
            type_tree: None,
            len_tree: None,
            initial_len: usize::MAX,
        }
    }
}

impl BlockTypeState {
    const fn new(spec: &BlockTypeInfo) -> Self {
        Self {
            ring: [1, 0],
            block_type: 0,
            remaining: spec.initial_len,
        }
    }

    fn prepare_next(
        &mut self,
        reader: &mut BitReader<'_>,
        spec: &BlockTypeInfo,
    ) -> Result<usize, Error> {
        if spec.num_types == 1 {
            return Ok(0);
        }
        if self.remaining == 0 {
            self.switch_block(reader, spec)?;
        }
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(Error::InvalidData("brotli: invalid block length"))?;
        Ok(self.block_type)
    }

    fn switch_block(
        &mut self,
        reader: &mut BitReader<'_>,
        spec: &BlockTypeInfo,
    ) -> Result<(), Error> {
        let type_tree = spec
            .type_tree
            .as_ref()
            .ok_or(Error::InvalidData("brotli: missing block type tree"))?;
        let len_tree = spec
            .len_tree
            .as_ref()
            .ok_or(Error::InvalidData("brotli: missing block length tree"))?;

        let block_type_code = type_tree.decode_symbol(reader)? as usize;
        let block_type = if block_type_code == 1 {
            self.ring[1] + 1
        } else if block_type_code == 0 {
            self.ring[0]
        } else {
            block_type_code
                .checked_sub(2)
                .ok_or(Error::InvalidData("brotli: invalid block type code"))?
        };
        // RFC 7932 §6: block type values must be in [0, NBLTYPES-1].
        if block_type >= spec.num_types {
            return Err(Error::InvalidData(
                "brotli: block type out of range for NBLTYPES",
            ));
        }

        self.ring[0] = self.ring[1];
        self.ring[1] = block_type;
        self.block_type = block_type;
        self.remaining = read_block_length(reader, len_tree)?;
        Ok(())
    }
}

fn parse_window_bits(reader: &mut BitReader<'_>) -> Result<u8, Error> {
    if reader.read_bits(1)? == 0 {
        return Ok(16);
    }

    let n = reader.read_bits(3)? as u8;
    if n != 0 {
        return Ok(17 + n);
    }

    let n = reader.read_bits(3)? as u8;
    // RFC 7932 §9.1: the bit pattern yielding WBITS=9 is reserved
    // and must not be used; valid small-window values are 10-15.
    if n == 1 {
        return Err(Error::InvalidData("brotli: invalid window bits"));
    }
    if n != 0 {
        return Ok(8 + n);
    }

    Ok(17)
}

fn parse_metablock_header(reader: &mut BitReader<'_>) -> Result<MetablockHeader, Error> {
    let is_last = reader.read_bits(1)? != 0;
    if is_last && reader.read_bits(1)? != 0 {
        reader.align_to_byte_if_zero()?;
        return Ok(MetablockHeader::LastEmpty);
    }

    let len_nibbles = parse_metablock_length_nibbles(reader)?;
    if len_nibbles == 0 {
        if reader.read_bits(1)? != 0 {
            return Err(Error::InvalidData("brotli: non-zero metadata reserved bit"));
        }
        let skip_bytes = reader.read_bits(2)? as usize;
        let skip_len = if skip_bytes == 0 {
            0
        } else {
            let bits = u8::try_from(skip_bytes * 8)
                .map_err(|_| Error::InvalidData("brotli: invalid metadata length width"))?;
            let skip_len_minus_one = reader.read_bits(bits)? as usize;
            if skip_bytes > 1 && ((skip_len_minus_one >> ((skip_bytes - 1) * 8)) & 0xFF) == 0 {
                return Err(Error::InvalidData("brotli: non-canonical metadata length"));
            }
            skip_len_minus_one
                .checked_add(1)
                .ok_or(Error::InvalidData("brotli: metadata length overflow"))?
        };
        return Ok(MetablockHeader::Metadata { skip_len });
    }

    let len_minus_one = reader.read_bits(len_nibbles * 4)? as usize;
    if len_nibbles > 4 && (len_minus_one >> ((len_nibbles as usize - 1) * 4)) == 0 {
        return Err(Error::InvalidData("brotli: non-canonical metablock length"));
    }
    let len = len_minus_one
        .checked_add(1)
        .ok_or(Error::InvalidData("brotli: metablock length overflow"))?;

    if is_last {
        return Ok(MetablockHeader::Compressed { is_last, len });
    }

    if reader.read_bits(1)? != 0 {
        return Ok(MetablockHeader::Uncompressed { is_last, len });
    }

    Ok(MetablockHeader::Compressed { is_last, len })
}

fn parse_metablock_length_nibbles(reader: &mut BitReader<'_>) -> Result<u8, Error> {
    match reader.read_bits(2)? {
        0 => Ok(4),
        1 => Ok(5),
        2 => Ok(6),
        3 => Ok(0),
        _ => unreachable!(),
    }
}

fn parse_compressed_metablock_info(
    reader: &mut BitReader<'_>,
) -> Result<CompressedMetablockInfo, Error> {
    let literal_block_types = read_block_type_info(reader)?;
    let insert_copy_block_types = read_block_type_info(reader)?;
    let distance_block_types = read_block_type_info(reader)?;
    let nbltypes_l = literal_block_types.num_types;
    let nbltypes_i = insert_copy_block_types.num_types;
    let nbltypes_d = distance_block_types.num_types;

    let npostfix = reader.read_bits(2)? as u8;
    let ndirect = (reader.read_bits(4)? as usize) << npostfix;

    let mut context_modes = Vec::with_capacity(nbltypes_l);
    for _ in 0..nbltypes_l {
        context_modes.push(reader.read_bits(2)? as u8);
    }

    let ntrees_l = read_var_len_uint8(reader)?;
    let literal_context_map = if ntrees_l >= 2 {
        read_context_map(reader, 64 * nbltypes_l, ntrees_l)?
    } else {
        vec![0; 64 * nbltypes_l]
    };

    let ntrees_d = read_var_len_uint8(reader)?;
    let distance_context_map = if ntrees_d >= 2 {
        read_context_map(reader, 4 * nbltypes_d, ntrees_d)?
    } else {
        vec![0; 4 * nbltypes_d]
    };

    let mut literal_trees = Vec::with_capacity(ntrees_l);
    for _ in 0..ntrees_l {
        literal_trees.push(huffman::read_prefix_code(reader, 256, 15)?);
    }
    let mut insert_copy_trees = Vec::with_capacity(nbltypes_i);
    for _ in 0..nbltypes_i {
        insert_copy_trees.push(huffman::read_prefix_code(reader, 704, 15)?);
    }
    let distance_alphabet_size = 16 + ndirect + (48usize << npostfix);
    let mut distance_trees = Vec::with_capacity(ntrees_d);
    for _ in 0..ntrees_d {
        distance_trees.push(huffman::read_prefix_code(
            reader,
            distance_alphabet_size,
            15,
        )?);
    }

    Ok(CompressedMetablockInfo {
        nbltypes_l,
        nbltypes_i,
        nbltypes_d,
        literal_block_types,
        insert_copy_block_types,
        distance_block_types,
        npostfix,
        ndirect,
        context_modes,
        ntrees_l,
        ntrees_d,
        literal_context_map,
        distance_context_map,
        literal_trees,
        insert_copy_trees,
        distance_trees,
    })
}

fn read_var_len_uint8(reader: &mut BitReader<'_>) -> Result<usize, Error> {
    if reader.read_bits(1)? == 0 {
        return Ok(1);
    }
    let nbits = reader.read_bits(3)? as u8;
    if nbits == 0 {
        return Ok(2);
    }
    Ok((reader.read_bits(nbits)? as usize) + (1usize << nbits) + 1)
}

fn read_block_type_info(reader: &mut BitReader<'_>) -> Result<BlockTypeInfo, Error> {
    let num_types = read_var_len_uint8(reader)?;
    if num_types > 256 {
        return Err(Error::InvalidData("brotli: invalid number of block types"));
    }
    if num_types == 1 {
        return Ok(BlockTypeInfo::single());
    }

    let type_tree = huffman::read_prefix_code(reader, num_types + 2, 15)?;
    let len_tree = huffman::read_prefix_code(reader, 26, 15)?;
    let initial_len = read_block_length(reader, &len_tree)?;
    Ok(BlockTypeInfo {
        num_types,
        type_tree: Some(type_tree),
        len_tree: Some(len_tree),
        initial_len,
    })
}

fn read_block_length(
    reader: &mut BitReader<'_>,
    tree: &huffman::HuffmanTable,
) -> Result<usize, Error> {
    let symbol = tree.decode_symbol(reader)? as usize;
    let Some(&offset) = BLOCK_LENGTH_PREFIX_OFFSETS.get(symbol) else {
        return Err(Error::InvalidData("brotli: invalid block length symbol"));
    };
    let extra_bits = BLOCK_LENGTH_PREFIX_EXTRA_BITS[symbol];
    Ok(offset + reader.read_bits(extra_bits)? as usize)
}

fn read_context_map(
    reader: &mut BitReader<'_>,
    size: usize,
    ntrees: usize,
) -> Result<Vec<u8>, Error> {
    let rlemax = if reader.read_bits(1)? == 0 {
        0usize
    } else {
        (reader.read_bits(4)? as usize) + 1
    };
    let table = huffman::read_prefix_code(reader, ntrees + rlemax, 15)?;
    let mut map = Vec::with_capacity(size);
    while map.len() < size {
        let symbol = table.decode_symbol(reader)? as usize;
        if symbol == 0 {
            map.push(0);
        } else if symbol <= rlemax {
            let repeat = (1usize << symbol) + (reader.read_bits(symbol as u8)? as usize);
            if map.len() + repeat > size {
                return Err(Error::InvalidData("brotli: context map repeat overflow"));
            }
            map.resize(map.len() + repeat, 0);
        } else {
            let value = symbol - rlemax;
            if value >= ntrees {
                return Err(Error::InvalidData("brotli: invalid context map tree"));
            }
            map.push(
                u8::try_from(value)
                    .map_err(|_| Error::InvalidData("brotli: invalid context map tree"))?,
            );
        }
    }

    if reader.read_bits(1)? != 0 {
        inverse_move_to_front(&mut map);
    }

    let mut seen = vec![false; ntrees];
    for &value in &map {
        let index = value as usize;
        if index >= ntrees {
            return Err(Error::InvalidData("brotli: invalid context map tree"));
        }
        seen[index] = true;
    }
    if seen.iter().any(|&used| !used) {
        return Err(Error::InvalidData(
            "brotli: non-canonical context map trees",
        ));
    }

    Ok(map)
}

fn inverse_move_to_front(values: &mut [u8]) {
    let mut mtf = [0u8; 256];
    for (index, value) in mtf.iter_mut().enumerate() {
        *value = index as u8;
    }
    for value in values {
        let index = *value as usize;
        let moved = mtf[index];
        for i in (1..=index).rev() {
            mtf[i] = mtf[i - 1];
        }
        mtf[0] = moved;
        *value = moved;
    }
}

fn decode_compressed_metablock(
    reader: &mut BitReader<'_>,
    header: &CompressedMetablockInfo,
    output: &mut Vec<u8>,
    len: usize,
    is_last: bool,
    window_size: usize,
    recent_distances: &mut RecentDistances,
) -> Result<(), Error> {
    let target_len = output
        .len()
        .checked_add(len)
        .ok_or(Error::InvalidData("brotli: metablock length overflow"))?;

    output.reserve(len);
    let mut literal_blocks = BlockTypeState::new(&header.literal_block_types);
    let mut insert_copy_blocks = BlockTypeState::new(&header.insert_copy_block_types);
    let mut distance_blocks = BlockTypeState::new(&header.distance_block_types);

    while output.len() < target_len {
        let insert_copy_block_type =
            insert_copy_blocks.prepare_next(reader, &header.insert_copy_block_types)?;
        let command = decode_command(reader, &header.insert_copy_trees[insert_copy_block_type])?;
        let literal_target = output
            .len()
            .checked_add(command.insert_len)
            .ok_or(Error::InvalidData("brotli: literal length overflow"))?;
        if literal_target > target_len {
            return Err(Error::InvalidData(
                "brotli: command exceeds metablock length",
            ));
        }

        for _ in 0..command.insert_len {
            let literal_block_type =
                literal_blocks.prepare_next(reader, &header.literal_block_types)?;
            let literal_tree_index = literal_tree_index(header, output, literal_block_type)?;
            let literal = header.literal_trees[literal_tree_index].decode_symbol(reader)?;
            let byte = u8::try_from(literal)
                .map_err(|_| Error::InvalidData("brotli: invalid literal symbol"))?;
            output.push(byte);
        }

        if output.len() == target_len {
            break;
        }

        let (distance, should_push_distance) = if let Some(distance_code) = command.distance_code {
            if distance_code == 0 {
                (recent_distances.last(), false)
            } else {
                (recent_distances.resolve_short_code(distance_code)?, true)
            }
        } else {
            let distance_block_type =
                distance_blocks.prepare_next(reader, &header.distance_block_types)?;
            let distance_tree_index =
                distance_tree_index(header, command.distance_context, distance_block_type);
            decode_distance(
                reader,
                &header.distance_trees[distance_tree_index],
                header.npostfix,
                header.ndirect,
                recent_distances,
            )?
        };

        let max_allowed_distance = output.len().min(window_size);
        if distance == 0 {
            return Err(Error::InvalidData("brotli: invalid backward distance"));
        }
        if distance > max_allowed_distance {
            dictionary::copy_static_dictionary_word(
                output,
                distance,
                command.copy_len,
                max_allowed_distance,
            )?;
        } else {
            let copy_target = output
                .len()
                .checked_add(command.copy_len)
                .ok_or(Error::InvalidData("brotli: copy length overflow"))?;
            if copy_target > target_len {
                return Err(Error::InvalidData(
                    "brotli: command exceeds metablock length",
                ));
            }

            copy_from_distance(output, distance, command.copy_len)?;
        }
        if output.len() > target_len {
            return Err(Error::InvalidData(
                "brotli: command exceeds metablock length",
            ));
        }
        // RFC 7932 section 4 / section 10: distances that resolve to
        // static dictionary references are not pushed to the ring
        // buffer of last distances.
        if should_push_distance && distance <= max_allowed_distance {
            recent_distances.push(distance);
        }
    }

    if is_last {
        reader.align_to_byte_if_zero()?;
    }

    Ok(())
}

fn literal_tree_index(
    header: &CompressedMetablockInfo,
    output: &[u8],
    block_type: usize,
) -> Result<usize, Error> {
    if header.ntrees_l == 1 {
        return Ok(0);
    }
    let p1 = output.last().copied().unwrap_or(0);
    let p2 = if output.len() >= 2 {
        output[output.len() - 2]
    } else {
        0
    };
    let context_mode = *header
        .context_modes
        .get(block_type)
        .ok_or(Error::InvalidData("brotli: invalid literal block type"))?;
    let context_id = literal_context_id(context_mode, p1, p2)?;
    let context_map_index = block_type
        .checked_mul(64)
        .and_then(|base| base.checked_add(context_id))
        .ok_or(Error::InvalidData("brotli: literal context index overflow"))?;
    Ok(*header
        .literal_context_map
        .get(context_map_index)
        .ok_or(Error::InvalidData("brotli: invalid literal context map"))? as usize)
}

const fn literal_context_id(mode: u8, p1: u8, p2: u8) -> Result<usize, Error> {
    let context = match mode {
        0 => p1 & 0x3F,
        1 => p1 >> 2,
        2 => utf8_last_byte_context(p1) | utf8_second_last_byte_context(p2),
        3 => signed_last_byte_context(p1) | signed_second_last_byte_context(p2),
        _ => return Err(Error::InvalidData("brotli: invalid literal context mode")),
    };
    Ok(context as usize)
}

const fn utf8_last_byte_context(byte: u8) -> u8 {
    match byte {
        0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F => 0,
        b'\t' | b'\n' | b'\r' => 4,
        b' ' => 8,
        b'"' | b'\'' => 16,
        b'%' => 20,
        b'(' | b'<' | b'[' | b'{' => 24,
        b')' | b'>' | b']' | b'}' => 28,
        b',' | b';' | b':' => 32,
        b'.' => 36,
        b'=' => 40,
        b'0'..=b'9' => 44,
        b'A' | b'E' | b'I' | b'O' | b'U' => 48,
        b'B'..=b'D' | b'F'..=b'H' | b'J'..=b'N' | b'P'..=b'T' | b'V'..=b'Z' => 52,
        b'a' | b'e' | b'i' | b'o' | b'u' => 56,
        b'b'..=b'd' | b'f'..=b'h' | b'j'..=b'n' | b'p'..=b't' | b'v'..=b'z' => 60,
        0x80..=0xBF => byte & 1,
        0xC0..=0xFF => 2 | (byte & 1),
        _ => 12,
    }
}

const fn utf8_second_last_byte_context(byte: u8) -> u8 {
    match byte {
        0x00..=0x20 | 0x7F | 0x80..=0xDF => 0,
        b'!'..=b'/' | b':'..=b'@' | b'['..=b'`' | b'{'..=b'~' => 1,
        b'0'..=b'9' | b'A'..=b'Z' | 0xE0..=0xFF => 2,
        b'a'..=b'z' => 3,
    }
}

const fn signed_last_byte_context(byte: u8) -> u8 {
    match byte {
        0 => 0,
        1..=15 => 8,
        16..=63 => 16,
        64..=127 => 24,
        128..=191 => 32,
        192..=239 => 40,
        240..=254 => 48,
        255 => 56,
    }
}

const fn signed_second_last_byte_context(byte: u8) -> u8 {
    match byte {
        0 => 0,
        1..=15 => 1,
        16..=63 => 2,
        64..=127 => 3,
        128..=191 => 4,
        192..=239 => 5,
        240..=254 => 6,
        255 => 7,
    }
}

fn distance_tree_index(
    header: &CompressedMetablockInfo,
    context_id: usize,
    block_type: usize,
) -> usize {
    if header.ntrees_d == 1 {
        return 0;
    }
    header.distance_context_map[(block_type << 2) + context_id] as usize
}

fn decode_command(
    reader: &mut BitReader<'_>,
    tree: &huffman::HuffmanTable,
) -> Result<Command, Error> {
    let symbol = tree.decode_symbol(reader)? as usize;
    let cell_idx = symbol >> 6;
    let Some(&cell_pos) = COMMAND_CELL_POS.get(cell_idx) else {
        return Err(Error::InvalidData("brotli: invalid command symbol"));
    };

    let insert_code = (cell_pos & 0x18) + ((symbol >> 3) & 0x7);
    let copy_code = ((cell_pos << 3) & 0x18) + (symbol & 0x7);
    let copy_len_offset = COPY_LENGTH_OFFSETS[copy_code];
    let insert_len = INSERT_LENGTH_OFFSETS[insert_code]
        + (reader.read_bits(INSERT_LENGTH_EXTRA_BITS[insert_code])? as usize);
    let copy_len =
        copy_len_offset + (reader.read_bits(COPY_LENGTH_EXTRA_BITS[copy_code])? as usize);

    Ok(Command {
        insert_len,
        copy_len,
        distance_context: if copy_len_offset > 4 {
            3
        } else {
            copy_len_offset - 2
        },
        distance_code: if cell_idx >= 2 { None } else { Some(0) },
    })
}

fn decode_distance(
    reader: &mut BitReader<'_>,
    tree: &huffman::HuffmanTable,
    npostfix: u8,
    ndirect: usize,
    recent_distances: &RecentDistances,
) -> Result<(usize, bool), Error> {
    let code = tree.decode_symbol(reader)? as usize;
    if code <= 15 {
        return Ok((recent_distances.resolve_short_code(code)?, code != 0));
    }
    if code <= 15 + ndirect {
        return Ok((code - 15, true));
    }

    let npostfix_usize = usize::from(npostfix);
    let ndistbits = 1 + ((code - ndirect - 16) >> (npostfix_usize + 1));
    let dextra = reader.read_bits(
        u8::try_from(ndistbits)
            .map_err(|_| Error::InvalidData("brotli: invalid distance width"))?,
    )? as usize;
    let postfix_mask = (1usize << npostfix_usize) - 1;
    let hcode = (code - ndirect - 16) >> npostfix_usize;
    let lcode = (code - ndirect - 16) & postfix_mask;
    let offset = ((2 + (hcode & 1)) << ndistbits) - 4;
    Ok((
        ((offset + dextra) << npostfix_usize) + lcode + ndirect + 1,
        true,
    ))
}

fn copy_from_distance(output: &mut Vec<u8>, distance: usize, copy_len: usize) -> Result<(), Error> {
    if distance == 0 || distance > output.len() {
        return Err(Error::InvalidData("brotli: invalid backward distance"));
    }

    for _ in 0..copy_len {
        let src = output.len() - distance;
        let byte = output[src];
        output.push(byte);
    }
    Ok(())
}

/// Decode a Brotli stream with a maximum output size limit.
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

    fn push_bits(bits: &mut Vec<u8>, value: u32, nbits: u8) {
        for i in 0..nbits {
            bits.push(((value >> i) & 1) as u8);
        }
    }

    fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut current = 0u8;
        for (index, bit) in bits.iter().copied().enumerate() {
            current |= bit << (index % 8);
            if index % 8 == 7 {
                bytes.push(current);
                current = 0;
            }
        }
        if !bits.len().is_multiple_of(8) {
            bytes.push(current);
        }
        bytes
    }

    fn align_zero(bits: &mut Vec<u8>) {
        while !bits.len().is_multiple_of(8) {
            bits.push(0);
        }
    }

    fn build_stream_prefix() -> Vec<u8> {
        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 1);
        push_bits(&mut bits, 1, 3); // window bits = 18
        bits
    }

    fn build_uncompressed_stream(chunks: &[&[u8]], add_final_empty: bool) -> Vec<u8> {
        let mut bits = build_stream_prefix();

        for (index, chunk) in chunks.iter().enumerate() {
            let is_last = index + 1 == chunks.len() && !add_final_empty;
            push_bits(&mut bits, u32::from(is_last), 1);
            if is_last {
                push_bits(&mut bits, 0, 1); // last but not empty
            }

            let len = chunk.len();
            let (len_nibbles_code, len_nibbles) = if len <= 0x1_0000 {
                (0u32, 4u8)
            } else if len <= 0x10_0000 {
                (1u32, 5u8)
            } else if len <= 0x100_0000 {
                (2u32, 6u8)
            } else {
                panic!("chunk too large for test helper");
            };
            push_bits(&mut bits, len_nibbles_code, 2);
            push_bits(&mut bits, (len - 1) as u32, len_nibbles * 4);
            if !is_last {
                push_bits(&mut bits, 1, 1); // uncompressed flag
            }
            align_zero(&mut bits);
            let mut bytes = bits_to_bytes(&bits);
            bytes.extend_from_slice(chunk);
            bits.clear();
            for byte in bytes {
                push_bits(&mut bits, byte as u32, 8);
            }
        }

        if add_final_empty {
            push_bits(&mut bits, 1, 1);
            push_bits(&mut bits, 1, 1);
        }

        bits_to_bytes(&bits)
    }

    fn build_metadata_stream(metadata: &[u8]) -> Vec<u8> {
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 0, 1); // not last
        push_bits(&mut bits, 3, 2); // MNIBBLES = 0
        push_bits(&mut bits, 0, 1); // reserved = 0

        if metadata.is_empty() {
            push_bits(&mut bits, 0, 2);
        } else {
            let skip_bytes = if metadata.len() <= 0x100 {
                1u32
            } else if metadata.len() <= 0x1_0000 {
                2u32
            } else if metadata.len() <= 0x100_0000 {
                3u32
            } else {
                panic!("metadata too large for test helper");
            };
            push_bits(&mut bits, skip_bytes, 2);
            push_bits(
                &mut bits,
                (metadata.len() - 1) as u32,
                (skip_bytes as u8) * 8,
            );
        }

        align_zero(&mut bits);
        let mut bytes = bits_to_bytes(&bits);
        bytes.extend_from_slice(metadata);
        bytes.push(0x03); // final empty metablock
        bytes
    }

    fn build_last_empty_stream_with_padding(padding_bits: &[u8]) -> Vec<u8> {
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 1, 1);
        push_bits(&mut bits, 1, 1);
        bits.extend_from_slice(padding_bits);
        bits_to_bytes(&bits)
    }

    fn build_minimal_compressed_header_stream() -> Vec<u8> {
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 1, 1); // is_last
        push_bits(&mut bits, 0, 1); // not last-empty
        push_bits(&mut bits, 0, 2); // mnibbles = 4
        push_bits(&mut bits, 0, 16); // len = 1
        push_bits(&mut bits, 0, 1); // nbltypes_l = 1
        push_bits(&mut bits, 0, 1); // nbltypes_i = 1
        push_bits(&mut bits, 0, 1); // nbltypes_d = 1
        push_bits(&mut bits, 0, 2); // npostfix
        push_bits(&mut bits, 0, 4); // ndirect
        push_bits(&mut bits, 0, 2); // context mode
        push_bits(&mut bits, 0, 1); // ntrees_l = 1
        push_bits(&mut bits, 0, 1); // ntrees_d = 1

        // literal prefix code: simple singleton symbol 65 ('A')
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 65, 8);
        // insert/copy prefix code: simple singleton symbol 0
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 0, 10);
        // distance prefix code: simple singleton symbol 0
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 0, 6);

        bits_to_bytes(&bits)
    }

    fn build_literal_block_switch_stream() -> Vec<u8> {
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 1, 1); // is_last
        push_bits(&mut bits, 0, 1); // not last-empty
        push_bits(&mut bits, 0, 2); // mnibbles = 4
        push_bits(&mut bits, 3, 16); // len = 4

        // literal block types = 2
        push_bits(&mut bits, 1, 1);
        push_bits(&mut bits, 0, 3);
        // literal block type tree: singleton symbol 0 -> switch to block type 1
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 0, 2);
        // literal block length tree: singleton symbol 0
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 0, 5);
        // initial literal block length = 2
        push_bits(&mut bits, 1, 2);

        // insert/copy block types = 1
        push_bits(&mut bits, 0, 1);
        // distance block types = 1
        push_bits(&mut bits, 0, 1);

        push_bits(&mut bits, 0, 2); // npostfix
        push_bits(&mut bits, 0, 4); // ndirect
        push_bits(&mut bits, 0, 2); // context mode for literal block type 0
        push_bits(&mut bits, 0, 2); // context mode for literal block type 1

        // ntrees_l = 2
        push_bits(&mut bits, 1, 1);
        push_bits(&mut bits, 0, 3);

        // literal context map
        push_bits(&mut bits, 1, 1); // use RLE for zeros
        push_bits(&mut bits, 5, 4); // rlemax = 6
        // prefix code over symbols [6, 7]
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 6, 3);
        push_bits(&mut bits, 7, 3);
        // 64 zeros
        push_bits(&mut bits, 0, 1);
        push_bits(&mut bits, 0, 6);
        // 64 ones
        for _ in 0..64 {
            push_bits(&mut bits, 1, 1);
        }
        push_bits(&mut bits, 0, 1); // IMTF disabled

        // ntrees_d = 1
        push_bits(&mut bits, 0, 1);

        // literal prefix trees: 'A', then 'B'
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 65, 8);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 66, 8);

        // insert/copy tree: singleton command symbol 32 => insert 4, copy 2
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 32, 10);

        // distance tree: singleton symbol 0 (unused)
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 0, 6);

        // switched literal block length = 2
        push_bits(&mut bits, 1, 2);

        // The metablock ends mid-byte; `bits_to_bytes` pads the
        // remaining bits with zeros as required by RFC 7932 section 9.3.
        bits_to_bytes(&bits)
    }

    #[test]
    fn test_decode_empty_stream() {
        assert_eq!(decode(&[0x33]).unwrap(), b"");
    }

    #[test]
    fn test_decode_uncompressed_hello_stream() {
        let input = [
            0x83, 0x06, 0x80, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x42, 0x72, 0x6f, 0x74,
            0x6c, 0x69, 0x21, 0x03,
        ];
        assert_eq!(decode(&input).unwrap(), b"Hello, Brotli!");
    }

    #[test]
    fn test_parse_window_bits_default_large() {
        let mut reader = BitReader::new(&[0x00]);
        assert_eq!(parse_window_bits(&mut reader).unwrap(), 16);
    }

    #[test]
    fn test_parse_window_bits_extended() {
        let mut reader = BitReader::new(&[0x03]);
        assert_eq!(parse_window_bits(&mut reader).unwrap(), 18);
    }

    #[test]
    fn test_parse_window_bits_rejects_reserved_pattern() {
        // RFC 7932 section 9.1: the bit pattern for WBITS=9 is reserved
        // and must not be used (bits: 1, then 000, then 001).
        let mut reader = BitReader::new(&[0x11]);
        assert!(matches!(
            parse_window_bits(&mut reader),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_last_metablock_rejects_nonzero_trailing_padding() {
        // RFC 7932 section 9.3: unused bits in the last byte must be
        // zero. The block-switch stream ends with one padding bit.
        let mut stream = build_literal_block_switch_stream();
        let last = stream.last_mut().unwrap();
        assert_eq!(*last & 0x80, 0, "test stream must end mid-byte");
        *last |= 0x80;
        assert!(matches!(decode(&stream), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_parse_metadata_header() {
        let stream = build_metadata_stream(b"meta");
        let mut reader = BitReader::new(&stream);
        parse_window_bits(&mut reader).unwrap();
        assert_eq!(
            parse_metablock_header(&mut reader).unwrap(),
            MetablockHeader::Metadata { skip_len: 4 }
        );
    }

    #[test]
    fn test_decode_metadata_then_empty() {
        let stream = build_metadata_stream(b"meta");
        assert_eq!(decode(&stream).unwrap(), b"");
    }

    #[test]
    fn test_last_empty_padding_must_be_zero() {
        let stream = build_last_empty_stream_with_padding(&[1, 0, 0, 0]);
        assert!(matches!(decode(&stream), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_metadata_reserved_bit_rejected() {
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 0, 1);
        push_bits(&mut bits, 3, 2);
        push_bits(&mut bits, 1, 1);
        let stream = bits_to_bytes(&bits);
        assert!(matches!(decode(&stream), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_invalid_compressed_metablock_rejected() {
        let input = [
            0x83, 0x06, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x42, 0x72, 0x6f, 0x74,
            0x6c, 0x69, 0x21, 0x03,
        ];
        assert!(matches!(
            decode(&input),
            Err(Error::Unsupported(_)) | Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_read_var_len_uint8_examples() {
        let mut one = BitReader::new(&[0x00]);
        assert_eq!(read_var_len_uint8(&mut one).unwrap(), 1);

        let mut two = BitReader::new(&[0x01]);
        assert_eq!(read_var_len_uint8(&mut two).unwrap(), 2);

        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 1);
        push_bits(&mut bits, 1, 3);
        push_bits(&mut bits, 1, 1);
        let four_bytes = bits_to_bytes(&bits);
        let mut four = BitReader::new(&four_bytes);
        assert_eq!(read_var_len_uint8(&mut four).unwrap(), 4);
    }

    #[test]
    fn test_parse_minimal_compressed_metablock_info() {
        let stream = build_minimal_compressed_header_stream();
        let mut reader = BitReader::new(&stream);
        parse_window_bits(&mut reader).unwrap();
        let header = parse_metablock_header(&mut reader).unwrap();
        let len = match header {
            MetablockHeader::Compressed { len, .. } => len,
            _ => panic!("expected compressed header"),
        };
        assert_eq!(len, 1);
        let info = parse_compressed_metablock_info(&mut reader).unwrap();
        assert_eq!(info.nbltypes_l, 1);
        assert_eq!(info.nbltypes_i, 1);
        assert_eq!(info.nbltypes_d, 1);
        assert_eq!(info.literal_block_types, BlockTypeInfo::single());
        assert_eq!(info.insert_copy_block_types, BlockTypeInfo::single());
        assert_eq!(info.distance_block_types, BlockTypeInfo::single());
        assert_eq!(info.npostfix, 0);
        assert_eq!(info.ndirect, 0);
        assert_eq!(info.context_modes, vec![0]);
        assert_eq!(info.ntrees_l, 1);
        assert_eq!(info.ntrees_d, 1);
        assert_eq!(info.literal_context_map, vec![0; 64]);
        assert_eq!(info.distance_context_map, vec![0; 4]);
        let mut empty = BitReader::new(&[]);
        assert_eq!(info.literal_trees[0].decode_symbol(&mut empty).unwrap(), 65);
        assert_eq!(
            info.insert_copy_trees[0].decode_symbol(&mut empty).unwrap(),
            0
        );
        assert_eq!(info.distance_trees[0].decode_symbol(&mut empty).unwrap(), 0);
    }

    #[test]
    fn test_parse_compressed_metablock_info_with_literal_block_switch() {
        let stream = build_literal_block_switch_stream();
        let mut reader = BitReader::new(&stream);
        parse_window_bits(&mut reader).unwrap();
        let header = parse_metablock_header(&mut reader).unwrap();
        let len = match header {
            MetablockHeader::Compressed { len, .. } => len,
            _ => panic!("expected compressed header"),
        };
        assert_eq!(len, 4);
        let info = parse_compressed_metablock_info(&mut reader).unwrap();
        assert_eq!(info.nbltypes_l, 2);
        assert_eq!(info.nbltypes_i, 1);
        assert_eq!(info.nbltypes_d, 1);
        assert_eq!(info.literal_block_types.initial_len, 2);
        assert_eq!(info.literal_context_map[..64], [0; 64]);
        assert!(
            info.literal_context_map[64..]
                .iter()
                .all(|&value| value == 1)
        );
    }

    #[test]
    fn test_block_type_state_switches_block_types() {
        let spec = BlockTypeInfo {
            num_types: 2,
            type_tree: Some(huffman::HuffmanTable::from_simple_code(&[0], None, 4, 15).unwrap()),
            len_tree: Some(huffman::HuffmanTable::from_simple_code(&[0], None, 26, 15).unwrap()),
            initial_len: 1,
        };
        let mut state = BlockTypeState::new(&spec);
        let mut reader = BitReader::new(&[0b0000_0001]);
        assert_eq!(state.prepare_next(&mut reader, &spec).unwrap(), 0);
        assert_eq!(state.prepare_next(&mut reader, &spec).unwrap(), 1);
    }

    #[test]
    fn test_short_distance_code_uses_initial_ring_buffer() {
        let distances = RecentDistances::new();
        assert_eq!(distances.resolve_short_code(0).unwrap(), 4);
        assert_eq!(distances.resolve_short_code(1).unwrap(), 11);
        assert_eq!(distances.resolve_short_code(8).unwrap(), 1);
    }

    #[test]
    fn test_decode_command_uses_reference_distance_metadata() {
        let tree = huffman::HuffmanTable::from_simple_code(&[190], None, 704, 15).unwrap();
        let mut reader = BitReader::new(&[0x00]); // insert extra bit = 0
        assert_eq!(
            decode_command(&mut reader, &tree).unwrap(),
            Command {
                insert_len: 8,
                copy_len: 8,
                distance_context: 3,
                distance_code: None,
            }
        );
    }

    #[test]
    fn test_decode_command_last_distance_reuse_metadata() {
        let tree = huffman::HuffmanTable::from_simple_code(&[0], None, 704, 15).unwrap();
        let mut reader = BitReader::new(&[]);
        assert_eq!(
            decode_command(&mut reader, &tree).unwrap(),
            Command {
                insert_len: 0,
                copy_len: 2,
                distance_context: 0,
                distance_code: Some(0),
            }
        );
    }

    #[test]
    fn test_decode_minimal_compressed_single_tree_stream() {
        let input = [0xa1, 0xf8, 0x01, 0x00, 0x00, 0x11, 0x14, 0xcf, 0x04, 0x92];
        assert_eq!(decode(&input).unwrap(), vec![b'A'; 64]);
    }

    #[test]
    fn test_decode_compressed_stream_with_literal_block_switch() {
        assert_eq!(
            decode(&build_literal_block_switch_stream()).unwrap(),
            b"AABB"
        );
    }

    #[test]
    fn test_brotli_decode_static_dictionary_identity_reference() {
        let input = [
            0xa1, 0xf8, 0x07, 0x00, 0x20, 0xc3, 0xf4, 0xca, 0xcf, 0x4b, 0x8d, 0x48, 0x43, 0x7c,
            0xd1, 0x30, 0xc1, 0x0f, 0x0b, 0x80, 0x08, 0x13, 0xca, 0xf8, 0xfc, 0x18, 0x00, 0xc2,
            0xd6, 0x85, 0x54, 0xda, 0x58, 0xe7, 0x43, 0x4c, 0xb9, 0xd4, 0xd6, 0x87, 0x71, 0x9a,
            0x97, 0x75, 0xdb, 0x8f, 0xf3, 0xba, 0x9f, 0xf7, 0xfb, 0x1b,
        ];
        let expected = (0u8..64).cycle().take(256).collect::<Vec<_>>();
        assert_eq!(decode(&input).unwrap(), expected);
    }

    #[test]
    fn test_read_context_map_without_rle() {
        let mut bits = Vec::new();
        push_bits(&mut bits, 0, 1); // rlemax = 0
        push_bits(&mut bits, 1, 2); // simple prefix
        push_bits(&mut bits, 1, 2); // nsym = 2
        push_bits(&mut bits, 0, 1); // symbol 0
        push_bits(&mut bits, 1, 1); // symbol 1
        push_bits(&mut bits, 0, 1); // value 0
        push_bits(&mut bits, 1, 1); // value 1
        push_bits(&mut bits, 1, 1); // value 1
        push_bits(&mut bits, 0, 1); // value 0
        push_bits(&mut bits, 0, 1); // imtf = false
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        assert_eq!(
            read_context_map(&mut reader, 4, 2).unwrap(),
            vec![0, 1, 1, 0]
        );
    }

    #[test]
    fn test_inverse_move_to_front_context_map() {
        let mut values = vec![0, 1, 1, 0, 2];
        inverse_move_to_front(&mut values);
        assert_eq!(values, vec![0, 1, 0, 0, 2]);
    }

    #[test]
    fn test_decode_last_uncompressed_metablock() {
        let input = build_uncompressed_stream(&[b"last block"], true);
        assert_eq!(decode(&input).unwrap(), b"last block");
    }

    #[test]
    fn test_decode_multiple_uncompressed_metablocks() {
        let input = build_uncompressed_stream(&[b"hello ", b"brotli"], true);
        assert_eq!(decode(&input).unwrap(), b"hello brotli");
    }

    #[test]
    fn test_decode_large_uncompressed_metablock_uses_five_nibbles() {
        let chunk = vec![b'a'; 70_000];
        let input = build_uncompressed_stream(&[&chunk], true);
        let decoded = decode(&input).unwrap();
        assert_eq!(decoded.len(), chunk.len());
        assert!(decoded.iter().all(|&byte| byte == b'a'));
    }

    #[test]
    fn test_context_lookup_tables_match_rfc7932_reference() {
        // Full reference lookup tables from the brotli C source / RFC 7932.
        // These cover all 256 byte values exhaustively.

        const REF_UTF8_P1: [u8; 256] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12, 44, 44, 44, 44,
            44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12, 12, 48, 52, 52, 52, 48, 52, 52, 52, 48,
            52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
            12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
            60, 60, 60, 60, 60, 24, 12, 28, 12, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
            0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
            2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2,
            3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
        ];

        const REF_UTF8_P2: [u8; 256] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        ];

        const REF_SIGNED_P1: [u8; 256] = [
            0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
            16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
            16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 24, 24, 24, 24, 24, 24,
            24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
            24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
            24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
            40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
            40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 56,
        ];

        const REF_SIGNED_P2: [u8; 256] = [
            0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
            5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
        ];

        // Validate utf8_last_byte_context against the reference table
        for byte in 0u16..=255 {
            let byte = byte as u8;
            assert_eq!(
                utf8_last_byte_context(byte),
                REF_UTF8_P1[byte as usize],
                "utf8_last_byte_context mismatch at byte 0x{byte:02X}"
            );
        }

        // Validate utf8_second_last_byte_context against the reference table
        for byte in 0u16..=255 {
            let byte = byte as u8;
            assert_eq!(
                utf8_second_last_byte_context(byte),
                REF_UTF8_P2[byte as usize],
                "utf8_second_last_byte_context mismatch at byte 0x{byte:02X}"
            );
        }

        // Validate signed_last_byte_context against the reference table
        for byte in 0u16..=255 {
            let byte = byte as u8;
            assert_eq!(
                signed_last_byte_context(byte),
                REF_SIGNED_P1[byte as usize],
                "signed_last_byte_context mismatch at byte 0x{byte:02X}"
            );
        }

        // Validate signed_second_last_byte_context against the reference table
        for byte in 0u16..=255 {
            let byte = byte as u8;
            assert_eq!(
                signed_second_last_byte_context(byte),
                REF_SIGNED_P2[byte as usize],
                "signed_second_last_byte_context mismatch at byte 0x{byte:02X}"
            );
        }
    }

    #[test]
    fn test_literal_context_p2_single_byte_output_uses_zero() {
        // When output has exactly 1 byte, p2 should be 0 (no second-to-last byte),
        // not output[0] (which was the bug: saturating_sub(2) gave index 0).
        //
        // In Signed context mode (mode 3):
        //   signed_second_last_byte_context(0) = 0
        //   signed_second_last_byte_context(0x13) = 2  (16..=63 bucket)
        // These differ, so using the wrong p2 selects the wrong Huffman tree.
        //
        // We verify by checking context_id directly:
        // With p1=0x13, p2=0: context_id = 16 | 0 = 16
        // With p1=0x13, p2=0x13 (bug): context_id = 16 | 2 = 18
        assert_eq!(literal_context_id(3, 0x13, 0).unwrap(), 16);
        assert_ne!(literal_context_id(3, 0x13, 0x13).unwrap(), 16);

        // Also verify all four context modes for single-byte scenarios:
        // Mode 0 (LSB6): p2 is unused, so no difference
        assert_eq!(literal_context_id(0, 0x42, 0).unwrap(), 0x42 & 0x3F);

        // Mode 1 (MSB6): p2 is unused, so no difference
        assert_eq!(literal_context_id(1, 0x42, 0).unwrap(), 0x42 >> 2);

        // Mode 2 (UTF-8): p2=0 should give second_last=0
        let utf8_p2_zero = utf8_second_last_byte_context(0);
        let utf8_p2_nonzero = utf8_second_last_byte_context(b'a');
        assert_eq!(utf8_p2_zero, 0);
        assert_ne!(utf8_p2_nonzero, 0);
        // So with p1=b'a' and single-byte output, context_id must use p2=0
        assert_eq!(
            literal_context_id(2, b'a', 0).unwrap(),
            (utf8_last_byte_context(b'a') | utf8_p2_zero) as usize
        );
    }

    #[test]
    fn test_literal_context_id_signed_matches_reference_ranges() {
        assert_eq!(literal_context_id(3, 0x00, 0x00).unwrap(), 0);
        assert_eq!(literal_context_id(3, 0x05, 0x10).unwrap(), 10);
        assert_eq!(literal_context_id(3, 0x80, 0xC0).unwrap(), 37);
        assert_eq!(literal_context_id(3, 0xFF, 0xFF).unwrap(), 63);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"hello brotli bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"hello brotli bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"hello brotli bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"hello brotli bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn test_decode_bounded_empty() {
        // Brotli empty stream: the byte 0x33 encodes an empty last metablock.
        let decoded = decode_bounded(&[0x33], 0).unwrap();
        assert!(decoded.is_empty());
    }

    /// Build the bit-level prefix of a last, compressed metablock whose
    /// metablock info uses single block types, NPOSTFIX = 0, NDIRECT = 0,
    /// one literal/distance tree each, a literal singleton 'A' tree, a
    /// simple insert-and-copy code over `ic_symbols`, and a distance
    /// singleton tree over symbol 16.  The caller appends command bits
    /// and converts with `bits_to_bytes`.
    fn build_compressed_metablock_bits(mlen: u32, ic_symbols: &[u16]) -> Vec<u8> {
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 1, 1); // is_last
        push_bits(&mut bits, 0, 1); // not last-empty
        push_bits(&mut bits, 0, 2); // MNIBBLES = 4
        push_bits(&mut bits, mlen - 1, 16); // MLEN - 1
        push_bits(&mut bits, 0, 1); // NBLTYPES_L = 1
        push_bits(&mut bits, 0, 1); // NBLTYPES_I = 1
        push_bits(&mut bits, 0, 1); // NBLTYPES_D = 1
        push_bits(&mut bits, 0, 2); // NPOSTFIX = 0
        push_bits(&mut bits, 0, 4); // NDIRECT = 0
        push_bits(&mut bits, 0, 2); // literal context mode = LSB6
        push_bits(&mut bits, 0, 1); // NTREES_L = 1
        push_bits(&mut bits, 0, 1); // NTREES_D = 1

        // literal prefix code: singleton 'A'
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 65, 8);

        // insert-and-copy prefix code: simple code over `ic_symbols`
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, (ic_symbols.len() - 1) as u32, 2);
        for &symbol in ic_symbols {
            push_bits(&mut bits, u32::from(symbol), 10);
        }

        // distance prefix code: singleton symbol 16
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 16, 6);

        bits
    }

    #[test]
    fn test_noncanonical_metablock_length_rejected() {
        // RFC 7932 section 9.2: when MNIBBLES > 4 the most significant
        // nibble of MLEN-1 must be non-zero.
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 0, 1); // ISLAST = 0
        push_bits(&mut bits, 1, 2); // MNIBBLES = 5
        push_bits(&mut bits, 0x0_FFFF, 20); // MLEN-1: top nibble is zero
        let stream = bits_to_bytes(&bits);
        let result = decode(&stream);
        assert!(
            matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("non-canonical metablock length")),
            "expected non-canonical metablock length rejection, got {result:?}"
        );
    }

    #[test]
    fn test_noncanonical_metadata_length_rejected() {
        // RFC 7932 section 9.2: when MSKIPBYTES > 1 the most
        // significant byte of MSKIPLEN-1 must be non-zero.
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 0, 1); // ISLAST = 0
        push_bits(&mut bits, 3, 2); // MNIBBLES = 0 (metadata block)
        push_bits(&mut bits, 0, 1); // reserved bit
        push_bits(&mut bits, 2, 2); // MSKIPBYTES = 2
        push_bits(&mut bits, 0x00FF, 16); // MSKIPLEN-1: top byte is zero
        let stream = bits_to_bytes(&bits);
        let result = decode(&stream);
        assert!(
            matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("non-canonical metadata length")),
            "expected non-canonical metadata length rejection, got {result:?}"
        );
    }

    #[test]
    fn test_metadata_nonzero_fill_bits_rejected() {
        // RFC 7932 section 9.2: the reserved fill bits between MSKIPLEN
        // and the skipped metadata bytes must be zero.
        let mut bits = build_stream_prefix();
        push_bits(&mut bits, 0, 1); // ISLAST = 0
        push_bits(&mut bits, 3, 2); // MNIBBLES = 0 (metadata block)
        push_bits(&mut bits, 0, 1); // reserved bit
        push_bits(&mut bits, 1, 2); // MSKIPBYTES = 1
        push_bits(&mut bits, 0, 8); // MSKIPLEN-1 = 0 (skip one byte)
        push_bits(&mut bits, 1, 1); // non-zero fill bit
        let stream = bits_to_bytes(&bits);
        assert!(matches!(decode(&stream), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_command_exceeding_metablock_length_rejected() {
        // RFC 7932 section 9.3: a command must not produce more than
        // MLEN bytes.  Covers insert-length overflow, backward-copy
        // overflow, and dictionary-copy overflow.  All trees are
        // singletons, so the command bodies consume no bits.
        for (mlen, ic_symbol) in [(1u32, 16u16), (5, 34), (2, 10)] {
            let bits = build_compressed_metablock_bits(mlen, &[ic_symbol]);
            let stream = bits_to_bytes(&bits);
            let result = decode(&stream);
            assert!(
                matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("exceeds metablock length")),
                "mlen {mlen} symbol {ic_symbol}: expected rejection, got {result:?}"
            );
        }
    }

    #[test]
    fn test_context_map_rejects_unused_tree_index() {
        // RFC 7932 section 7.3: NTREES is the number of distinct tree
        // indices appearing in the context map; every index must be
        // used.  Here the map fills all four entries with tree 0 while
        // NTREES = 2.
        let mut bits = Vec::new();
        push_bits(&mut bits, 0, 1); // RLEMAX = 0
        // prefix code over two symbols [0, 1]
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 1);
        push_bits(&mut bits, 1, 1);
        // context map: four entries, all tree index 0
        for _ in 0..4 {
            push_bits(&mut bits, 0, 1);
        }
        push_bits(&mut bits, 0, 1); // inverse move-to-front disabled
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let result = read_context_map(&mut reader, 4, 2);
        assert!(
            matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("non-canonical context map trees")),
            "expected non-canonical context map rejection, got {result:?}"
        );
    }

    #[test]
    fn test_dictionary_distance_not_pushed_to_recent_ring() {
        // RFC 7932 section 4 / section 10: a distance that resolves to
        // a static dictionary reference must not update the ring
        // buffer of last distances.
        let header = CompressedMetablockInfo {
            nbltypes_l: 1,
            nbltypes_i: 1,
            nbltypes_d: 1,
            literal_block_types: BlockTypeInfo::single(),
            insert_copy_block_types: BlockTypeInfo::single(),
            distance_block_types: BlockTypeInfo::single(),
            npostfix: 0,
            ndirect: 0,
            context_modes: vec![0],
            ntrees_l: 1,
            ntrees_d: 1,
            literal_context_map: vec![0; 64],
            distance_context_map: vec![0; 4],
            literal_trees: vec![
                huffman::HuffmanTable::from_simple_code(&[65], None, 256, 15).unwrap(),
            ],
            insert_copy_trees: vec![
                huffman::HuffmanTable::from_simple_code(&[2, 130], None, 704, 15).unwrap(),
            ],
            distance_trees: vec![
                huffman::HuffmanTable::from_simple_code(&[16], None, 64, 15).unwrap(),
            ],
        };

        // Command bits (LSB first):
        //   cmd1: ic symbol 130 -> explicit distance, 1 extra bit = 0
        //         -> distance 1, a dictionary reference to word "time"
        //         (output is empty, so max distance is 0)
        //   cmd2: ic symbol 2 -> implicit distance code 0 (last distance)
        //   cmd3: ic symbol 130 -> explicit distance, 1 extra bit = 1
        //         -> distance 2, a normal backward copy that is pushed
        let body = [0b0001_1001u8];
        let mut reader = BitReader::new(&body);
        let mut output = Vec::new();
        let mut recent = RecentDistances::new();
        decode_compressed_metablock(
            &mut reader,
            &header,
            &mut output,
            12,
            true,
            65520,
            &mut recent,
        )
        .unwrap();

        assert_eq!(&output[..8], b"timetime");
        assert_eq!(&output[8..], b"meme");
        // Only the normal backward copy (distance 2) was pushed; the
        // dictionary distance 1 left the ring untouched, so the
        // implicit distance-0 command still resolved to the initial
        // last distance 4.
        assert_eq!(recent.ring, [2, 15, 11, 4]);
        assert_eq!(recent.index, 1);
        assert_eq!(recent.last(), 2);
    }

    #[test]
    fn test_decode_dictionary_reference_preserves_distance_ring() {
        // End-to-end form of the above: command 1 copies dictionary
        // word "time" (distance 1 > max distance 0), command 2 copies
        // 4 bytes at the implicit last distance.  With a correct ring
        // the last distance is the initial value 4, producing
        // "time" + "time"; if the dictionary distance were pushed,
        // distance 1 would be reused and the output would be
        // "time" + "eeee".
        let mut bits = build_compressed_metablock_bits(8, &[2, 130]);
        push_bits(&mut bits, 1, 1); // cmd1: ic symbol 130
        push_bits(&mut bits, 0, 1); // distance extra bit -> distance 1
        push_bits(&mut bits, 0, 1); // cmd2: ic symbol 2 (implicit distance 0)
        let stream = bits_to_bytes(&bits);
        assert_eq!(decode(&stream).unwrap(), b"timetime");
    }
}
