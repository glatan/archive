use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Huffman decoding table for zstd literals.
#[derive(Debug, Clone)]
pub(crate) struct HuffmanTable {
    entries: Vec<(u8, u8)>, // (symbol, num_bits)
    max_bits: u8,
}

impl HuffmanTable {
    /// Build a Huffman table from weights.
    ///
    /// Weights are 0..=max_number_of_bits. Weight 0 means symbol not present.
    /// Actual number of bits for a symbol = max_bits + 1 - weight.
    pub(crate) fn from_weights(weights: &[u8]) -> Result<Self, Error> {
        if weights.is_empty() {
            return Ok(Self {
                entries: Vec::new(),
                max_bits: 0,
            });
        }

        let max_weight = *weights.iter().max().unwrap();
        if max_weight == 0 {
            return Ok(Self {
                entries: Vec::new(),
                max_bits: 0,
            });
        }

        // Sum weights to find total
        let weight_sum: u32 = weights
            .iter()
            .filter(|&&w| w > 0)
            .map(|&w| 1u32 << (w - 1))
            .sum();

        // max_bits = ceil(log2(weight_sum))
        let max_bits = highest_bit_ceil(weight_sum);

        // RFC 8878 §4.2.1: total weight must be a power of 2
        if weight_sum != 0 && (weight_sum & (weight_sum - 1)) != 0 {
            return Err(Error::InvalidData(
                "zstd Huffman weight sum is not a power of 2",
            ));
        }

        if max_bits > 11 {
            return Err(Error::InvalidData(
                "zstd Huffman code length exceeds 11 bits",
            ));
        }
        if max_bits == 0 {
            return Ok(Self {
                entries: Vec::new(),
                max_bits: 0,
            });
        }

        let table_size = 1usize << max_bits;
        let mut entries = vec![(0u8, 0u8); table_size];
        let mut symbols: Vec<(u8, u8)> = weights
            .iter()
            .enumerate()
            .filter_map(|(symbol, &weight)| {
                if weight == 0 {
                    None
                } else {
                    Some((weight, symbol as u8))
                }
            })
            .collect();
        symbols.sort_unstable_by_key(|&(weight, symbol)| (weight, symbol));

        let mut next_code = 0usize;
        for &(weight, symbol) in &symbols {
            let code_len = max_bits + 1 - weight;
            let fill = 1usize << (max_bits - code_len);
            let end = next_code + fill;
            if end > table_size {
                return Err(Error::InvalidData("zstd Huffman code space overflow"));
            }
            for entry in &mut entries[next_code..end] {
                *entry = (symbol, code_len);
            }
            next_code = end;
        }
        if next_code != table_size {
            return Err(Error::InvalidData("zstd Huffman code space underflow"));
        }

        Ok(Self { entries, max_bits })
    }

    /// Decode one symbol from a bit stream using the top `max_bits` bits.
    pub(crate) fn decode_symbol(&self, bits: u32) -> (u8, u8) {
        if self.entries.is_empty() {
            return (0, 0);
        }
        let mask = (1u32 << self.max_bits) - 1;
        let idx = (bits & mask) as usize;
        self.entries[idx]
    }

    pub(crate) const fn max_bits(&self) -> u8 {
        self.max_bits
    }
}

/// Parse Huffman weights from a compressed header.
/// Returns (weights, bytes_consumed).
pub(crate) fn parse_huffman_weights(data: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    if data.is_empty() {
        return Err(Error::UnexpectedEof);
    }

    let header_byte = data[0];

    if header_byte < 128 {
        // FSE-compressed weights
        let compressed_size = header_byte as usize;
        if 1 + compressed_size > data.len() {
            return Err(Error::UnexpectedEof);
        }
        let compressed_data = &data[1..1 + compressed_size];
        let weights = decompress_fse_weights(compressed_data)?;
        Ok((weights, 1 + compressed_size))
    } else {
        // Direct representation: 4-bit weights
        let num_symbols = (header_byte - 127) as usize;
        let bytes_needed = num_symbols.div_ceil(2);
        if 1 + bytes_needed > data.len() {
            return Err(Error::UnexpectedEof);
        }
        let mut weights = Vec::with_capacity(num_symbols);
        for i in 0..num_symbols {
            let byte = data[1 + i / 2];
            let weight = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
            weights.push(weight);
        }
        Ok((weights, 1 + bytes_needed))
    }
}

/// Append the implicitly encoded final Huffman weight.
///
/// RFC 8878 §4.2.1.2: the FSE stream carries at most 255 weights; the last
/// symbol's weight is deduced by completing the code space to the next power
/// of two.
pub(crate) fn complete_huffman_weights(weights: &mut Vec<u8>) -> Result<(), Error> {
    let weight_sum: u32 = weights
        .iter()
        .filter(|&&weight| weight > 0)
        .map(|&weight| 1u32 << (weight - 1))
        .sum();
    if weight_sum == 0 {
        return Ok(());
    }

    let table_log = 32 - weight_sum.leading_zeros();
    let target = 1u32 << table_log;
    let remaining = target - weight_sum;
    if remaining == 0 {
        return Ok(());
    }
    if !remaining.is_power_of_two() {
        return Err(Error::InvalidData(
            "zstd: implicit Huffman weight is not a power of 2",
        ));
    }
    weights.push(remaining.trailing_zeros() as u8 + 1);
    Ok(())
}

/// Decompress FSE-compressed Huffman weights.
fn decompress_fse_weights(data: &[u8]) -> Result<Vec<u8>, Error> {
    use super::fse::FseTable;

    // Build FSE table from the bitstream for weight decoding
    let (table, header_size) = FseTable::from_bitstream(data, 12, 6)?;

    // Decode weights using the FSE table
    // Read from the remaining data after the FSE header, using a reverse bit stream
    let bit_data = &data[header_size..];
    if bit_data.is_empty() {
        return Ok(Vec::new());
    }

    let mut weights = Vec::new();

    // Initialize reverse bit reader (MSB-first from the end of the stream)
    let mut bit_buf = 0u64;
    let mut bits_available = 0u8;
    let mut byte_pos = bit_data.len();

    // Find the leading 1 bit in the last byte to initialize
    if byte_pos > 0 {
        byte_pos -= 1;
        let last_byte = bit_data[byte_pos];
        if last_byte == 0 {
            return Err(Error::InvalidData("FSE stream: last byte is zero"));
        }
        let leading_zeros = last_byte.leading_zeros() as u8;
        let useful_bits = 8 - leading_zeros - 1; // exclude the sentinel bit
        bit_buf = (last_byte as u64) & ((1u64 << useful_bits) - 1);
        bits_available = useful_bits;
    }

    // Load more bits into the buffer
    let load_bits = |buf: &mut u64, avail: &mut u8, pos: &mut usize| {
        while *avail < 56 && *pos > 0 {
            *pos -= 1;
            *buf = (*buf << 8) | (bit_data[*pos] as u64);
            *avail += 8;
        }
    };

    load_bits(&mut bit_buf, &mut bits_available, &mut byte_pos);

    // Initialize two FSE states
    let al = table.accuracy_log;
    if bits_available < al * 2 {
        return Err(Error::UnexpectedEof);
    }

    let read_bits_rev = |buf: &mut u64, avail: &mut u8, n: u8| -> u32 {
        if n == 0 {
            return 0;
        }
        *avail -= n;
        let val = (*buf >> *avail) & ((1u64 << n) - 1);
        val as u32
    };

    let mut state1 = read_bits_rev(&mut bit_buf, &mut bits_available, al) as usize;
    let mut state2 = read_bits_rev(&mut bit_buf, &mut bits_available, al) as usize;

    loop {
        let entry1 = &table.entries[state1];
        weights.push(entry1.symbol);

        load_bits(&mut bit_buf, &mut bits_available, &mut byte_pos);

        if bits_available < entry1.num_bits {
            // End of stream after state2
            let entry2 = &table.entries[state2];
            weights.push(entry2.symbol);
            break;
        }

        state1 = entry1.baseline as usize
            + read_bits_rev(&mut bit_buf, &mut bits_available, entry1.num_bits) as usize;

        let entry2 = &table.entries[state2];
        weights.push(entry2.symbol);

        load_bits(&mut bit_buf, &mut bits_available, &mut byte_pos);

        if bits_available < entry2.num_bits {
            let final_entry = &table.entries[state1];
            weights.push(final_entry.symbol);
            break;
        }

        state2 = entry2.baseline as usize
            + read_bits_rev(&mut bit_buf, &mut bits_available, entry2.num_bits) as usize;
    }

    Ok(weights)
}

const fn highest_bit_ceil(val: u32) -> u8 {
    if val <= 1 {
        return 0;
    }
    (32 - (val - 1).leading_zeros()) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highest_bit_ceil() {
        assert_eq!(highest_bit_ceil(1), 0);
        assert_eq!(highest_bit_ceil(2), 1);
        assert_eq!(highest_bit_ceil(4), 2);
        assert_eq!(highest_bit_ceil(5), 3);
    }

    #[test]
    fn test_huffman_max_code_length_11bit() {
        // Valid: weights that produce code lengths up to 11 bits
        // weight_sum must be a power of 2 (RFC 8878 §4.2.1)
        // weights [1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        // weight_sum = 2*1 + 2 + 4 + 8 + 16 + 32 + 64 + 128 + 256 + 512 + 1024 = 2048 = 2^11
        // max_bits = 11, symbol 0 has code_length = 11+1-1 = 11
        let weights = vec![1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let table = HuffmanTable::from_weights(&weights);
        assert!(table.is_ok());
        assert_eq!(table.unwrap().max_bits(), 11);
    }

    #[test]
    fn test_huffman_code_length_exceeds_11bit_error() {
        // Invalid: weights that would produce code lengths > 11 bits
        // weights [1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        // weight_sum = 2*1+2+4+8+16+32+64+128+256+512+1024+2048 = 4096 = 2^12
        // max_bits = 12, symbol 0 has code_length = 12+1-1 = 12 > 11 → error
        let weights = vec![1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let result = HuffmanTable::from_weights(&weights);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_huffman_weight_sum_not_power_of_2() {
        // weights [1, 2] → weight_sum = 1 + 2 = 3 (not a power of 2)
        let result = HuffmanTable::from_weights(&[1, 2]);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_direct_weights() {
        // Header byte = 127 + 2 = 129 (2 symbols)
        // One byte with two 4-bit weights: (3 << 4) | 2 = 0x32
        let data = [129, 0x32];
        let (weights, consumed) = parse_huffman_weights(&data).unwrap();
        assert_eq!(weights, vec![3, 2]);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_from_weights_empty() {
        let table = HuffmanTable::from_weights(&[]).unwrap();
        assert_eq!(table.max_bits(), 0);
        assert!(table.entries.is_empty());
    }

    #[test]
    fn test_from_weights_all_zero() {
        let table = HuffmanTable::from_weights(&[0, 0, 0]).unwrap();
        assert_eq!(table.max_bits(), 0);
        assert!(table.entries.is_empty());
    }

    #[test]
    fn test_from_weights_two_symbols() {
        // Two symbols with equal weight: weights [1, 1]
        // weight_sum = 2^0 + 2^0 = 2, max_bits = 1
        // code_lengths: 1+1-1=1, 1+1-1=1
        let table = HuffmanTable::from_weights(&[1, 1]).unwrap();
        assert_eq!(table.max_bits(), 1);
        // Table has 2 entries (1-bit codes)
        assert_eq!(table.entries.len(), 2);
        // Each 1-bit code maps to a different symbol
        let (sym0, bits0) = table.decode_symbol(0);
        let (sym1, bits1) = table.decode_symbol(1);
        assert_eq!(bits0, 1);
        assert_eq!(bits1, 1);
        assert_ne!(sym0, sym1);
    }

    #[test]
    fn test_from_weights_unequal() {
        // weights [2, 1, 1] → weight_sum = 2^1 + 2^0 + 2^0 = 4
        // max_bits = 2
        // zstd assigns codes by ascending weight, then symbol order.
        let table = HuffmanTable::from_weights(&[2, 1, 1]).unwrap();
        assert_eq!(table.max_bits(), 2);
        let (sym0, bits0) = table.decode_symbol(0b00);
        let (sym1, bits1) = table.decode_symbol(0b01);
        let (sym2, bits2) = table.decode_symbol(0b10);
        assert_eq!((sym0, bits0), (1, 2));
        assert_eq!((sym1, bits1), (2, 2));
        assert_eq!((sym2, bits2), (0, 1));
    }

    #[test]
    fn test_decode_symbol_empty_table() {
        let table = HuffmanTable::from_weights(&[]).unwrap();
        let (sym, bits) = table.decode_symbol(42);
        assert_eq!(sym, 0);
        assert_eq!(bits, 0);
    }

    #[test]
    fn test_parse_huffman_weights_truncated() {
        // Header byte 129 = direct, 2 symbols, needs 1 data byte
        // But only provide header byte with no data
        let result = parse_huffman_weights(&[129]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_huffman_weights_fse_compressed_zero() {
        // Header byte 0 means FSE-compressed with size=0, which is invalid
        let result = parse_huffman_weights(&[0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_huffman_weights_fse_truncated() {
        // Header byte 5 means FSE-compressed with size=5, but only 3 bytes provided
        let result = parse_huffman_weights(&[5, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_direct_weights_odd_count() {
        // 3 symbols: header = 127 + 3 = 130
        // 2 bytes: first byte has weights[0] and weights[1], second has weights[2] and padding
        let data = [130, (4 << 4) | 3, 2 << 4];
        let (weights, consumed) = parse_huffman_weights(&data).unwrap();
        assert_eq!(weights, vec![4, 3, 2]);
        assert_eq!(consumed, 3); // 1 header + 2 data bytes
    }

    #[test]
    fn test_decompress_fse_weights_via_roundtrip() {
        // Encode data large enough to trigger Huffman literal compression,
        // then decode it. This indirectly exercises decompress_fse_weights
        // since the decoder must parse FSE-compressed Huffman weight tables
        // from compressed blocks with Huffman literals.
        use crate::compress::zstd::{decode, encode};

        // 1KB of English text repeated — skewed byte distribution triggers Huffman
        let base = b"The quick brown fox jumps over the lazy dog. \
                     She sells seashells by the seashore. \
                     Peter Piper picked a peck of pickled peppers. ";
        let mut input = Vec::new();
        while input.len() < 4096 {
            input.extend_from_slice(base);
        }

        let encoded = encode::encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(
            decoded, input,
            "roundtrip mismatch for Huffman-compressed data"
        );

        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_parse_huffman_weights_infers_final_fse_weight() {
        // Huffman weight header from a zstd 1.5.7 `--train` dictionary.
        // The FSE stream carries 255 weights; symbol 255's weight is implied
        // by the remaining code space (RFC 8878 §4.2.1.2).
        let data = [0x09, 0x10, 0x10, 0xDF, 0x30, 0x33, 0x33, 0xB3, 0x77, 0x0A];
        let (mut weights, consumed) = parse_huffman_weights(&data).unwrap();

        assert_eq!(consumed, data.len());
        assert_eq!(weights.len(), 255);

        complete_huffman_weights(&mut weights).unwrap();
        let weight_sum: u32 = weights
            .iter()
            .filter(|&&weight| weight > 0)
            .map(|&weight| 1u32 << (weight - 1))
            .sum();

        assert_eq!(weights.len(), 256);
        assert_eq!(weight_sum, 512);
    }

    #[test]
    fn test_parse_huffman_weights_system_zstd_header_regression() {
        let data = [
            0x1B, 0x90, 0xB4, 0x6B, 0xC4, 0xC9, 0x23, 0xCA, 0x2B, 0x35, 0xE6, 0xA7, 0x3D, 0xC6,
            0xD0, 0x83, 0x30, 0x9E, 0xEF, 0x99, 0x44, 0x00, 0x00, 0x80, 0x88, 0x00, 0x00, 0x08,
        ];
        let (weights, consumed) = parse_huffman_weights(&data).unwrap();

        assert_eq!(consumed, data.len());
        assert_eq!(weights.len(), 126);
        assert!(weights.contains(&0));
        assert!(weights.iter().any(|&w| w > 0));
    }
}
