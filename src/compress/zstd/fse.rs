use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// An FSE (Finite State Entropy) decoding table entry.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FseEntry {
    pub(crate) symbol: u8,
    pub(crate) num_bits: u8,
    pub(crate) baseline: u16,
}

/// FSE decoding table.
#[derive(Debug, Clone)]
pub(crate) struct FseTable {
    pub(crate) entries: Vec<FseEntry>,
    pub(crate) accuracy_log: u8,
}

impl FseTable {
    /// Build an FSE table from normalized probabilities.
    ///
    /// `norm_probs[symbol]` is the probability for that symbol.
    /// Negative values (-1) indicate "less than 1" probability (symbol present but rare).
    pub(crate) fn from_probabilities(norm_probs: &[i16], accuracy_log: u8) -> Result<Self, Error> {
        let table_size = 1usize << accuracy_log;
        let mut entries = vec![FseEntry::default(); table_size];

        // Distribute symbols with probability >= 1
        let mut high_threshold = table_size - 1;
        let _cumulative = 0usize;

        // First pass: place symbols with prob == -1 at the high end
        let mut symbol_next = vec![0u32; norm_probs.len()];
        for (symbol, &prob) in norm_probs.iter().enumerate() {
            if prob == -1 {
                entries[high_threshold].symbol = symbol as u8;
                high_threshold -= 1;
                symbol_next[symbol] = 1;
            } else if prob > 0 {
                symbol_next[symbol] = prob as u32;
            }
        }

        // RFC 8878 §4.1.1: an FSE table description must contain at least
        // two symbols with non-zero probability ("less than 1" probabilities,
        // encoded as -1, count as non-zero).
        let nonzero_symbols = norm_probs.iter().filter(|&&p| p != 0).count();
        if nonzero_symbols < 2 {
            return Err(Error::InvalidData(
                "FSE table description needs at least two non-zero-probability symbols",
            ));
        }

        // Spread symbols across the table using the standard zstd distribution
        let step = (table_size >> 1) + (table_size >> 3) + 3;
        let table_mask = table_size - 1;
        let mut position = 0usize;

        for (symbol, &prob) in norm_probs.iter().enumerate() {
            if prob <= 0 {
                continue; // skip -1 (already placed) and 0 (unused)
            }
            for _ in 0..prob as usize {
                entries[position].symbol = symbol as u8;
                // Advance position, skipping positions >= high_threshold+1 that are used by -1 symbols
                loop {
                    position = (position + step) & table_mask;
                    if position <= high_threshold {
                        break;
                    }
                }
            }
        }

        if position != 0 {
            return Err(Error::InvalidData(
                "FSE table build: position didn't wrap to 0",
            ));
        }

        // Build decoding table: compute num_bits and baseline for each entry
        for entry in entries.iter_mut().take(table_size) {
            let symbol = entry.symbol;
            let next_state = symbol_next[symbol as usize];
            symbol_next[symbol as usize] += 1;

            let nb = accuracy_log as u32 - highest_bit(next_state);
            entry.num_bits = nb as u8;
            entry.baseline = ((next_state << nb) - table_size as u32) as u16;
        }

        Ok(FseTable {
            entries,
            accuracy_log,
        })
    }

    /// Build an FSE table from a compressed bitstream.
    /// Returns the table and number of bytes consumed.
    pub(crate) fn from_bitstream(
        data: &[u8],
        max_symbol: u8,
        max_accuracy_log: u8,
    ) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::UnexpectedEof);
        }

        let mut bit_pos = 0usize;
        let accuracy_log = read_bits_fse(data, &mut bit_pos, 4)? as u8 + 5;
        if accuracy_log > max_accuracy_log {
            return Err(Error::InvalidData("FSE accuracy log too large"));
        }

        let table_size = 1i32 << accuracy_log;
        let mut remaining = table_size + 1;
        let mut threshold = table_size;
        let mut nb_bits = accuracy_log + 1;
        let mut probs = vec![0i16; max_symbol as usize + 1];
        let mut symbol = 0usize;
        let mut previous_zero = false;

        while remaining > 1 && symbol <= max_symbol as usize {
            if previous_zero {
                let mut zero_run = 0usize;
                loop {
                    let repeat = read_bits_fse(data, &mut bit_pos, 2)? as usize;
                    zero_run += repeat;
                    if repeat < 3 {
                        break;
                    }
                }
                symbol += zero_run;
                if symbol > max_symbol as usize + 1 {
                    return Err(Error::InvalidData("FSE zero run exceeds symbol count"));
                }
            }

            if symbol > max_symbol as usize {
                break;
            }

            let max = (2 * threshold - 1) - remaining;
            let low = peek_bits_fse(data, bit_pos, nb_bits - 1)? as i32;
            let value = if low < max {
                read_bits_fse(data, &mut bit_pos, nb_bits - 1)? as i32
            } else {
                let mut value = read_bits_fse(data, &mut bit_pos, nb_bits)? as i32;
                if value >= threshold {
                    value -= max;
                }
                value
            };

            let prob = value - 1;
            probs[symbol] = prob as i16;
            symbol += 1;
            previous_zero = prob == 0;

            if prob >= 0 {
                remaining -= prob;
            } else {
                remaining += prob;
            }

            if remaining < threshold {
                if remaining <= 1 {
                    break;
                }
                nb_bits = (highest_bit(remaining as u32) + 1) as u8;
                threshold = 1 << (nb_bits - 1);
            }
        }

        if remaining != 1 {
            return Err(Error::InvalidData(
                "FSE probabilities do not sum to table size",
            ));
        }
        if symbol == 0 {
            return Err(Error::InvalidData("FSE table has no symbols"));
        }

        // RFC 8878 §4.1.1: the number of decoded symbols must not exceed
        // max_symbol + 1. A zero-run or bitstream corruption could push the
        // count past the declared maximum.
        if symbol > max_symbol as usize + 1 {
            return Err(Error::InvalidData("zstd: FSE table symbol count mismatch"));
        }

        let bytes_consumed = bit_pos.div_ceil(8);
        let table = FseTable::from_probabilities(&probs, accuracy_log)?;
        Ok((table, bytes_consumed))
    }
}

/// Read `n` bits from data at the given bit position (LSB-first within bytes).
fn read_bits_fse(data: &[u8], bit_pos: &mut usize, n: u8) -> Result<u32, Error> {
    if n == 0 {
        return Ok(0);
    }
    let byte_pos = *bit_pos / 8;
    let bit_offset = *bit_pos % 8;

    // Read enough bytes
    let mut value = 0u64;
    let bytes_needed = (bit_offset + n as usize).div_ceil(8);
    for i in 0..bytes_needed {
        if byte_pos + i >= data.len() {
            return Err(Error::UnexpectedEof);
        }
        value |= (data[byte_pos + i] as u64) << (i * 8);
    }

    value >>= bit_offset;
    let mask = (1u64 << n) - 1;
    *bit_pos += n as usize;
    Ok((value & mask) as u32)
}

fn peek_bits_fse(data: &[u8], bit_pos: usize, n: u8) -> Result<u32, Error> {
    let mut pos = bit_pos;
    read_bits_fse(data, &mut pos, n)
}

/// Return the position of the highest set bit (0-indexed from LSB).
/// highest_bit(1) = 0, highest_bit(2) = 1, highest_bit(4) = 2, etc.
const fn highest_bit(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    31 - val.leading_zeros()
}

/// Predefined FSE tables for literal lengths (from zstd spec).
pub(crate) fn default_literal_length_table() -> FseTable {
    let probs: [i16; 36] = [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
        1, 1, -1, -1, -1, -1,
    ];
    FseTable::from_probabilities(&probs, 6).unwrap()
}

/// Predefined FSE tables for match lengths.
pub(crate) fn default_match_length_table() -> FseTable {
    let probs: [i16; 53] = [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ];
    FseTable::from_probabilities(&probs, 6).unwrap()
}

/// Predefined FSE tables for offsets (RFC 8878, Table 18).
pub(crate) fn default_offset_table() -> FseTable {
    let probs: [i16; 29] = [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
    ];
    FseTable::from_probabilities(&probs, 5).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highest_bit() {
        assert_eq!(highest_bit(1), 0);
        assert_eq!(highest_bit(2), 1);
        assert_eq!(highest_bit(4), 2);
        assert_eq!(highest_bit(7), 2);
        assert_eq!(highest_bit(8), 3);
    }

    #[test]
    fn test_default_tables_build() {
        let _ll = default_literal_length_table();
        let _ml = default_match_length_table();
        let _of = default_offset_table();
    }

    // Phase 2: Verify default tables match RFC 8878 Appendix A

    #[test]
    fn test_default_ll_table_appendix_a() {
        let table = default_literal_length_table();
        assert_eq!(table.accuracy_log, 6);
        assert_eq!(table.entries.len(), 64);

        // Verify symbol distribution matches probabilities
        let probs: [i16; 36] = [
            4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1,
            1, 1, 1, -1, -1, -1, -1,
        ];
        let mut counts = [0u32; 36];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }
        for (sym, &prob) in probs.iter().enumerate() {
            let expected_count = if prob == -1 { 1 } else { prob as u32 };
            assert_eq!(counts[sym], expected_count, "symbol {} count mismatch", sym);
        }
    }

    #[test]
    fn test_default_ml_table_appendix_a() {
        let table = default_match_length_table();
        assert_eq!(table.accuracy_log, 6);
        assert_eq!(table.entries.len(), 64);

        let probs: [i16; 53] = [
            1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
        ];
        let mut counts = [0u32; 53];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }
        for (sym, &prob) in probs.iter().enumerate() {
            let expected_count = if prob == -1 { 1 } else { prob as u32 };
            assert_eq!(counts[sym], expected_count, "symbol {} count mismatch", sym);
        }
    }

    #[test]
    fn test_accuracy_log_upper_limit_rejection() {
        // RFC 8878 §4.1.1: Accuracy_Log for LL max=9, ML max=9, OF max=8
        // from_bitstream reads 4 bits + 5 = accuracy_log, so max_accuracy_log gates it.
        // Construct a bitstream where accuracy_log = 5+15 = 20 (way above any limit).
        // 4-bit field = 15 → accuracy_log = 20, which exceeds max_accuracy_log=9.
        let data = [0x0F]; // low 4 bits = 15
        let result = FseTable::from_bitstream(&data, 35, 9);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("accuracy log")),
            "expected error about accuracy log, got: {:?}",
            result
        );

        // Also test with max_accuracy_log=8 (offsets)
        // 4-bit field = 4 → accuracy_log = 9 > 8
        let data2 = [0x04];
        let result2 = FseTable::from_bitstream(&data2, 28, 8);
        assert!(
            matches!(result2, Err(Error::InvalidData(msg)) if msg.contains("accuracy log")),
            "expected error about accuracy log, got: {:?}",
            result2
        );
    }

    #[test]
    fn test_default_of_table_appendix_a() {
        let table = default_offset_table();
        assert_eq!(table.accuracy_log, 5);
        assert_eq!(table.entries.len(), 32);

        let probs: [i16; 29] = [
            1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1,
            -1,
        ];
        let mut counts = [0u32; 29];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }
        for (sym, &prob) in probs.iter().enumerate() {
            let expected_count = if prob == -1 { 1 } else { prob as u32 };
            assert_eq!(counts[sym], expected_count, "symbol {} count mismatch", sym);
        }
    }

    #[test]
    fn test_from_probabilities_rejects_fewer_than_two_nonzero_symbols() {
        // RFC 8878 §4.1.1: an FSE table description must have at least two
        // symbols with non-zero probability.
        let single = [0i16, 0, 0, 32, 0]; // one symbol fills the whole table (al=5)
        let result = FseTable::from_probabilities(&single, 5);
        assert!(
            matches!(result, Err(Error::InvalidData(_))),
            "expected InvalidData for single-symbol FSE table, got: {:?}",
            result.map(|t| t.entries.len())
        );

        // A single "less than 1" probability symbol (-1) is also insufficient.
        let rare = [0i16, -1, 0];
        assert!(matches!(
            FseTable::from_probabilities(&rare, 5),
            Err(Error::InvalidData(_))
        ));

        // All-zero probabilities are rejected as well.
        assert!(matches!(
            FseTable::from_probabilities(&[0i16; 4], 5),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_from_bitstream_rejects_single_symbol_description() {
        // Hand-crafted NCount table description: accuracy_log=5 (low nibble
        // 0), then one symbol with probability 32 filling the whole table.
        // RFC 8878 §4.1.1 requires >= 2 non-zero-probability symbols.
        let data = [0xF0, 0x03];
        let result = FseTable::from_bitstream(&data, 35, 9);
        assert!(
            matches!(result, Err(Error::InvalidData(_))),
            "expected InvalidData for 1-symbol FSE description, got: {:?}",
            result.map(|(t, _)| t.entries.len())
        );
    }

    #[test]
    fn test_from_bitstream_accepts_two_symbol_description() {
        // accuracy_log=5, symbols 0 and 1 with probability 16 each.
        let data = [0x10, 0x3F];
        let (table, consumed) = FseTable::from_bitstream(&data, 35, 9).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(table.accuracy_log, 5);
        assert_eq!(table.entries.len(), 32);
        let mut counts = [0u32; 2];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }
        assert_eq!(counts, [16, 16]);
    }

    #[test]
    fn test_from_bitstream_matches_system_zstd_weight_header() {
        let data = [0x90, 0xB4, 0x6B, 0xC4];
        let (table, consumed) = FseTable::from_bitstream(&data, 12, 6).unwrap();

        assert_eq!(table.accuracy_log, 5);
        assert_eq!(consumed, 3);

        let mut counts = [0u32; 13];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }
        assert_eq!(&counts[..6], &[8, 19, 4, 0, 0, 1]);
    }
}
