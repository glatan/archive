use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::bitreader::BitReader;

#[allow(dead_code)]
const CODE_LENGTH_CODE_ORDER: [u8; 18] =
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HuffmanTable {
    entries: Vec<(u16, u8)>,
    max_bits: u8,
    singleton: Option<u16>,
}

#[allow(dead_code)]
impl HuffmanTable {
    pub(crate) fn from_code_lengths(
        code_lengths: &[u8],
        max_bits_limit: u8,
    ) -> Result<Self, Error> {
        let non_zero: Vec<(usize, u8)> = code_lengths
            .iter()
            .copied()
            .enumerate()
            .filter(|&(_, len)| len != 0)
            .collect();
        if non_zero.is_empty() {
            return Err(Error::InvalidData("brotli: empty Huffman table"));
        }
        if non_zero.len() == 1 {
            return Ok(Self {
                entries: Vec::new(),
                max_bits: 0,
                singleton: Some(non_zero[0].0 as u16),
            });
        }

        let max_bits = non_zero.iter().map(|(_, len)| *len).max().unwrap_or(0);
        if max_bits > max_bits_limit {
            return Err(Error::InvalidData("brotli: Huffman code length too large"));
        }

        let mut bl_count = vec![0u32; max_bits as usize + 1];
        for (_, len) in &non_zero {
            bl_count[*len as usize] += 1;
        }

        let mut next_code = vec![0u32; max_bits as usize + 1];
        let mut code = 0u32;
        for bits in 1..=max_bits {
            code = (code + bl_count[(bits - 1) as usize]) << 1;
            next_code[bits as usize] = code;
        }

        let table_size = 1usize << max_bits;
        let mut entries = vec![(0u16, 0u8); table_size];
        for (symbol, len) in non_zero {
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            let reversed = reverse_bits(code, len);
            let step = 1usize << len;
            let mut index = reversed as usize;
            while index < table_size {
                entries[index] = (symbol as u16, len);
                index += step;
            }
        }

        Ok(Self {
            entries,
            max_bits,
            singleton: None,
        })
    }

    pub(crate) fn decode_symbol(&self, reader: &mut BitReader<'_>) -> Result<u16, Error> {
        if let Some(symbol) = self.singleton {
            return Ok(symbol);
        }
        let bits = reader.peek_bits(self.max_bits)? as usize;
        let (symbol, len) = self.entries[bits];
        if len == 0 {
            return Err(Error::InvalidData("brotli: invalid Huffman code"));
        }
        reader.consume(len);
        Ok(symbol)
    }

    pub(crate) fn from_simple_code(
        symbols: &[u16],
        tree_select: Option<bool>,
        alphabet_size: usize,
        max_bits_limit: u8,
    ) -> Result<Self, Error> {
        if symbols.len() == 1 {
            let symbol = *symbols
                .first()
                .ok_or(Error::InvalidData("brotli: missing simple prefix symbol"))?;
            if symbol as usize >= alphabet_size {
                return Err(Error::InvalidData("brotli: invalid simple prefix symbol"));
            }
            return Ok(Self {
                entries: Vec::new(),
                max_bits: 0,
                singleton: Some(symbol),
            });
        }
        let code_lengths = simple_code_lengths(symbols, tree_select, alphabet_size)?;
        Self::from_code_lengths(&code_lengths, max_bits_limit)
    }
}

#[allow(dead_code)]
fn reverse_bits(mut value: u32, num_bits: u8) -> u32 {
    let mut result = 0u32;
    for _ in 0..num_bits {
        result = (result << 1) | (value & 1);
        value >>= 1;
    }
    result
}

#[allow(dead_code)]
pub(crate) fn read_prefix_code(
    reader: &mut BitReader<'_>,
    alphabet_size: usize,
    max_bits_limit: u8,
) -> Result<HuffmanTable, Error> {
    let prefix_kind = reader.read_bits(2)?;
    if prefix_kind == 1 {
        return read_simple_prefix_code(reader, alphabet_size, max_bits_limit);
    }
    read_complex_prefix_code(reader, prefix_kind as u8, alphabet_size, max_bits_limit)
}

#[allow(dead_code)]
fn read_simple_prefix_code(
    reader: &mut BitReader<'_>,
    alphabet_size: usize,
    max_bits_limit: u8,
) -> Result<HuffmanTable, Error> {
    let nsym = reader.read_bits(2)? as usize + 1;
    let alphabet_bits = alphabet_bits(alphabet_size);
    let mut symbols = Vec::with_capacity(nsym);
    for _ in 0..nsym {
        let symbol = reader.read_bits(alphabet_bits)? as u16;
        if symbol as usize >= alphabet_size || symbols.contains(&symbol) {
            return Err(Error::InvalidData("brotli: invalid simple prefix symbol"));
        }
        symbols.push(symbol);
    }
    let tree_select = if nsym == 4 {
        Some(reader.read_bits(1)? != 0)
    } else {
        None
    };
    HuffmanTable::from_simple_code(&symbols, tree_select, alphabet_size, max_bits_limit)
}

#[allow(dead_code)]
fn read_complex_prefix_code(
    reader: &mut BitReader<'_>,
    hskip: u8,
    alphabet_size: usize,
    max_bits_limit: u8,
) -> Result<HuffmanTable, Error> {
    if hskip == 1 {
        return Err(Error::InvalidData("brotli: invalid complex prefix hskip"));
    }

    let code_length_code_lengths = read_code_length_code_lengths(reader, hskip)?;
    let code_length_table = HuffmanTable::from_code_lengths(&code_length_code_lengths, 5)?;
    let code_lengths = read_code_lengths(reader, &code_length_table, alphabet_size)?;

    HuffmanTable::from_code_lengths(&code_lengths, max_bits_limit)
}

#[allow(dead_code)]
fn read_code_length_code_lengths(reader: &mut BitReader<'_>, hskip: u8) -> Result<Vec<u8>, Error> {
    let mut code_lengths = vec![0u8; 18];
    let start_index = match hskip {
        0 => 0,
        2 => 2,
        3 => 3,
        _ => return Err(Error::InvalidData("brotli: invalid hskip value")),
    };

    let mut space = 32u32;
    let mut non_zero_count = 0usize;
    for &symbol in CODE_LENGTH_CODE_ORDER.iter().skip(start_index) {
        let len = read_small_code_length_code(reader)?;
        code_lengths[symbol as usize] = len;
        if len != 0 {
            space = space
                .checked_sub(32 >> len)
                .ok_or(Error::InvalidData("brotli: code length code overfull"))?;
            non_zero_count += 1;
            if space == 0 {
                break;
            }
        }
    }

    if non_zero_count == 1 || space == 0 {
        Ok(code_lengths)
    } else {
        Err(Error::InvalidData(
            "brotli: invalid code length code lengths",
        ))
    }
}

#[allow(dead_code)]
fn read_small_code_length_code(reader: &mut BitReader<'_>) -> Result<u8, Error> {
    const PREFIX_LENGTH: [u8; 16] = [2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4];
    const PREFIX_VALUE: [u8; 16] = [0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5];

    let ix = reader.peek_bits(4)? as usize;
    let len = PREFIX_LENGTH[ix];
    let value = PREFIX_VALUE[ix];
    reader.consume(len);
    Ok(value)
}

#[allow(dead_code)]
fn read_code_lengths(
    reader: &mut BitReader<'_>,
    table: &HuffmanTable,
    alphabet_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut code_lengths = vec![0u8; alphabet_size];
    let mut index = 0usize;
    let mut prev_non_zero = 8u8;
    let mut repeat_count = 0usize;
    let mut repeat_code_len = 0u8;
    let mut space = 32768u32;
    let mut non_zero_count = 0usize;

    while index < alphabet_size && space > 0 {
        let symbol = table.decode_symbol(reader)?;
        match symbol {
            0..=15 => {
                repeat_count = 0;
                let len = symbol as u8;
                code_lengths[index] = len;
                if len != 0 {
                    prev_non_zero = len;
                    space = space
                        .checked_sub(32768 >> len)
                        .ok_or(Error::InvalidData("brotli: prefix code overfull"))?;
                    non_zero_count += 1;
                }
                index += 1;
            }
            16 | 17 => {
                let (new_len, extra_bits) = if symbol == 16 {
                    (prev_non_zero, 2u8)
                } else {
                    (0u8, 3u8)
                };
                let repeat_delta = reader.read_bits(extra_bits)? as usize;
                if repeat_code_len != new_len {
                    repeat_count = 0;
                    repeat_code_len = new_len;
                }
                let old_repeat = repeat_count;
                if repeat_count > 0 {
                    repeat_count = repeat_count.saturating_sub(2) << extra_bits;
                }
                repeat_count = repeat_count
                    .checked_add(repeat_delta + 3)
                    .ok_or(Error::InvalidData("brotli: invalid repeat count"))?;
                let repeat_delta = repeat_count.saturating_sub(old_repeat);
                if index + repeat_delta > alphabet_size {
                    return Err(Error::InvalidData("brotli: code length repeat overflow"));
                }
                if new_len != 0 {
                    for slot in &mut code_lengths[index..index + repeat_delta] {
                        *slot = new_len;
                    }
                    let repeated_space = (32768u32 >> new_len)
                        .checked_mul(repeat_delta as u32)
                        .ok_or(Error::InvalidData("brotli: prefix code overfull"))?;
                    space = space
                        .checked_sub(repeated_space)
                        .ok_or(Error::InvalidData("brotli: prefix code overfull"))?;
                    non_zero_count += repeat_delta;
                }
                index += repeat_delta;
            }
            _ => return Err(Error::InvalidData("brotli: invalid code length symbol")),
        }
    }
    // RFC 7932 §3.5: a complex prefix code must have at least two non-zero
    // code lengths.  A single non-zero length is only valid as a simple prefix
    // code (§3.2), which is handled by a different code path.
    if non_zero_count >= 2 && space == 0 {
        Ok(code_lengths)
    } else if non_zero_count < 2 {
        Err(Error::InvalidData(
            "brotli: complex prefix code needs at least two non-zero code lengths",
        ))
    } else {
        Err(Error::InvalidData("brotli: invalid prefix code lengths"))
    }
}

#[allow(dead_code)]
pub(crate) fn simple_code_lengths(
    symbols: &[u16],
    tree_select: Option<bool>,
    alphabet_size: usize,
) -> Result<Vec<u8>, Error> {
    if alphabet_size == 0 {
        return Err(Error::InvalidData("brotli: empty alphabet"));
    }

    let mut code_lengths = vec![0u8; alphabet_size];
    match symbols {
        [a] => {
            code_lengths[*a as usize] = 0;
        }
        [a, b] => {
            code_lengths[*a as usize] = 1;
            code_lengths[*b as usize] = 1;
        }
        [a, b, c] => {
            code_lengths[*a as usize] = 1;
            code_lengths[*b as usize] = 2;
            code_lengths[*c as usize] = 2;
        }
        [a, b, c, d] => {
            if tree_select.unwrap_or(false) {
                code_lengths[*a as usize] = 1;
                code_lengths[*b as usize] = 2;
                code_lengths[*c as usize] = 3;
                code_lengths[*d as usize] = 3;
            } else {
                code_lengths[*a as usize] = 2;
                code_lengths[*b as usize] = 2;
                code_lengths[*c as usize] = 2;
                code_lengths[*d as usize] = 2;
            }
        }
        _ => {
            return Err(Error::InvalidData(
                "brotli: invalid simple prefix symbol count",
            ));
        }
    }
    Ok(code_lengths)
}

#[allow(dead_code)]
const fn alphabet_bits(alphabet_size: usize) -> u8 {
    let mut bits = 0u8;
    let mut limit = 1usize;
    while limit < alphabet_size {
        bits += 1;
        limit <<= 1;
    }
    bits
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

    fn encode_canonical_symbol(code_lengths: &[u8], symbol: usize, bits: &mut Vec<u8>) {
        let max_bits = *code_lengths.iter().max().unwrap_or(&0);
        let mut bl_count = vec![0u32; max_bits as usize + 1];
        for &len in code_lengths {
            if len != 0 {
                bl_count[len as usize] += 1;
            }
        }
        let mut next_code = vec![0u32; max_bits as usize + 1];
        let mut code = 0u32;
        for bit_len in 1..=max_bits {
            code = (code + bl_count[(bit_len - 1) as usize]) << 1;
            next_code[bit_len as usize] = code;
        }
        for (idx, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let current = next_code[len as usize];
            if idx == symbol {
                push_bits(bits, reverse_bits(current, len), len);
                return;
            }
            next_code[len as usize] += 1;
        }
        panic!("symbol not encodable");
    }

    #[test]
    fn test_build_and_decode_two_symbol_table() {
        let table = HuffmanTable::from_code_lengths(&[1, 1], 15).unwrap();
        let mut zero = BitReader::new(&[0x00]);
        let mut one = BitReader::new(&[0x01]);
        assert_eq!(table.decode_symbol(&mut zero).unwrap(), 0);
        assert_eq!(table.decode_symbol(&mut one).unwrap(), 1);
    }

    #[test]
    fn test_singleton_table_decodes_without_bits() {
        let table = HuffmanTable::from_code_lengths(&[0, 0, 5, 0], 15).unwrap();
        let mut reader = BitReader::new(&[]);
        assert_eq!(table.decode_symbol(&mut reader).unwrap(), 2);
    }

    #[test]
    fn test_empty_table_rejected() {
        assert!(matches!(
            HuffmanTable::from_code_lengths(&[0, 0, 0], 15),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_max_bits_limit_enforced() {
        assert!(matches!(
            HuffmanTable::from_code_lengths(&[16, 16], 15),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_simple_prefix_two_symbols() {
        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 2, 2);
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let table = read_prefix_code(&mut reader, 4, 15).unwrap();
        let mut zero = BitReader::new(&[0x00]);
        let mut one = BitReader::new(&[0x01]);
        assert_eq!(table.decode_symbol(&mut zero).unwrap(), 1);
        assert_eq!(table.decode_symbol(&mut one).unwrap(), 2);
    }

    #[test]
    fn test_simple_prefix_singleton() {
        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 0, 2);
        push_bits(&mut bits, 3, 2);
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let table = read_prefix_code(&mut reader, 4, 15).unwrap();
        let mut empty = BitReader::new(&[]);
        assert_eq!(table.decode_symbol(&mut empty).unwrap(), 3);
    }

    #[test]
    fn test_simple_prefix_four_symbols_tree_select_one() {
        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 3, 2);
        push_bits(&mut bits, 0, 3);
        push_bits(&mut bits, 1, 3);
        push_bits(&mut bits, 2, 3);
        push_bits(&mut bits, 3, 3);
        push_bits(&mut bits, 1, 1);
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let table = read_prefix_code(&mut reader, 8, 15).unwrap();
        let mut r0 = BitReader::new(&[0b0000_0000]);
        let mut r10 = BitReader::new(&[0b0000_0001]);
        let mut r110 = BitReader::new(&[0b0000_0011]);
        let mut r111 = BitReader::new(&[0b0000_0111]);
        assert_eq!(table.decode_symbol(&mut r0).unwrap(), 0);
        assert_eq!(table.decode_symbol(&mut r10).unwrap(), 1);
        assert_eq!(table.decode_symbol(&mut r110).unwrap(), 2);
        assert_eq!(table.decode_symbol(&mut r111).unwrap(), 3);
    }

    #[test]
    fn test_simple_prefix_duplicate_symbol_rejected() {
        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        push_bits(&mut bits, 1, 2);
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        assert!(matches!(
            read_prefix_code(&mut reader, 4, 15),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_complex_prefix_decodes_lengths_1233() {
        let mut bits = Vec::new();
        push_bits(&mut bits, 0, 2); // complex, hskip=0
        push_bits(&mut bits, 7, 4); // len(1)=1
        push_bits(&mut bits, 3, 3); // len(2)=2
        push_bits(&mut bits, 3, 3); // len(3)=2
        let code_length_code_lengths = {
            let mut v = vec![0u8; 18];
            v[1] = 1;
            v[2] = 2;
            v[3] = 2;
            v
        };
        encode_canonical_symbol(&code_length_code_lengths, 1, &mut bits);
        encode_canonical_symbol(&code_length_code_lengths, 2, &mut bits);
        encode_canonical_symbol(&code_length_code_lengths, 3, &mut bits);
        encode_canonical_symbol(&code_length_code_lengths, 3, &mut bits);

        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let table = read_prefix_code(&mut reader, 4, 15).unwrap();
        let mut r0 = BitReader::new(&[0b0000_0000]);
        let mut r10 = BitReader::new(&[0b0000_0001]);
        let mut r110 = BitReader::new(&[0b0000_0011]);
        let mut r111 = BitReader::new(&[0b0000_0111]);
        assert_eq!(table.decode_symbol(&mut r0).unwrap(), 0);
        assert_eq!(table.decode_symbol(&mut r10).unwrap(), 1);
        assert_eq!(table.decode_symbol(&mut r110).unwrap(), 2);
        assert_eq!(table.decode_symbol(&mut r111).unwrap(), 3);
    }

    #[test]
    fn test_complex_prefix_repeat_zero_overflow_rejected() {
        let table = HuffmanTable::from_simple_code(&[17, 1], None, 18, 5).unwrap();
        let mut bits = Vec::new();
        push_bits(&mut bits, 1, 1); // symbol 17
        push_bits(&mut bits, 7, 3); // repeat zero 10 times
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        assert!(matches!(
            read_code_lengths(&mut reader, &table, 4),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_complex_prefix_single_nonzero_code_length_rejected() {
        // RFC 7932 §3.5: a complex prefix code must have >= 2 non-zero code
        // lengths.  Build a code-length-code table that emits one non-zero
        // code length followed by enough zeros to fill the alphabet, then
        // verify the decoder rejects it.
        //
        // code-length-code: symbol 1 → bit 0, symbol 17 → bit 1
        let mut lengths = vec![0u8; 18];
        lengths[1] = 1;
        lengths[17] = 1;
        let table = HuffmanTable::from_code_lengths(&lengths, 5).unwrap();

        // Encode: symbol 1 (code length 1 for alphabet[0]), then symbol 17
        // (repeat zero × 3), which fills out a 4-symbol alphabet with only
        // one non-zero code length.
        let mut bits = Vec::new();
        push_bits(&mut bits, 0, 1); // symbol 1
        push_bits(&mut bits, 1, 1); // symbol 17
        push_bits(&mut bits, 0, 3); // repeat zero 3 times
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let result = read_code_lengths(&mut reader, &table, 4);
        assert!(
            matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("at least two")),
            "expected rejection of single non-zero code length, got {result:?}"
        );
    }

    #[test]
    fn test_complex_prefix_implicit_trailing_zeros() {
        let mut lengths = vec![0u8; 18];
        lengths[1] = 1;
        lengths[17] = 1;
        let table = HuffmanTable::from_code_lengths(&lengths, 5).unwrap();
        let mut reader = BitReader::new(&[0x00]);
        assert_eq!(
            read_code_lengths(&mut reader, &table, 8).unwrap(),
            vec![1, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_complex_prefix_repeat_previous_overflow_rejected() {
        // RFC 7932 section 3.5: a repeat-previous-non-zero code (16)
        // whose repeat count would extend past the end of the alphabet
        // must be rejected as "code length repeat overflow".
        let mut lengths = vec![0u8; 18];
        lengths[8] = 1;
        lengths[16] = 1;
        let table = HuffmanTable::from_code_lengths(&lengths, 5).unwrap();

        let mut bits = Vec::new();
        push_bits(&mut bits, 0, 1); // code length 8 for symbol 0
        push_bits(&mut bits, 1, 1); // symbol 16 (repeat previous non-zero)
        push_bits(&mut bits, 3, 2); // repeat 6 times -> index 7 > alphabet 4
        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        let result = read_code_lengths(&mut reader, &table, 4);
        assert!(
            matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("repeat overflow")),
            "expected code length repeat overflow rejection, got {result:?}"
        );
    }

    #[test]
    fn test_repeat_count_resets_between_16_and_17() {
        let mut table_lengths = vec![0u8; 18];
        table_lengths[2] = 1;
        table_lengths[16] = 2;
        table_lengths[17] = 2;
        let table = HuffmanTable::from_code_lengths(&table_lengths, 5).unwrap();

        let mut bits = Vec::new();
        encode_canonical_symbol(&table_lengths, 2, &mut bits);
        encode_canonical_symbol(&table_lengths, 16, &mut bits);
        push_bits(&mut bits, 0, 2); // repeat previous non-zero 3 times
        encode_canonical_symbol(&table_lengths, 17, &mut bits);
        push_bits(&mut bits, 0, 3); // repeat zero 3 times

        let bytes = bits_to_bytes(&bits);
        let mut reader = BitReader::new(&bytes);
        assert_eq!(
            read_code_lengths(&mut reader, &table, 7).unwrap(),
            vec![2, 2, 2, 2, 0, 0, 0]
        );
    }
}
