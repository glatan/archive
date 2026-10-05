//! PMarc `-pm1-` and `-pm2-` encoders — the encode mirror of `pmarc`.
//!
//! Both streams carry move-to-front byte literals selected through a
//! variable-length distance code, so a literal-only parse is a fully
//! valid stream: `-pm2-` emits one static 8-leaf code tree and flags
//! every later checkpoint "trees unchanged" (no offset tree is ever
//! present because `num_codes < 10`); `-pm1-` selects byte tree 6,
//! writes 216-literal blocks, and closes the final short block with a
//! dummy distance-0 copy the decoder parses but emits nothing from.

use alloc::vec::Vec;

use crate::compress::lzh::bits::MsbWriter;

use super::pmarc::{History, PM1_BYTE_RANGES, PM2_HISTORY, Vl};

/// Variable-length table index covering `dist`: the greatest entry
/// whose `offset` does not exceed it (tables are offset-sorted).
fn vl_index(table: &[Vl], dist: u32) -> usize {
    let mut i = table.len() - 1;
    while dist < table[i].offset {
        i -= 1;
    }
    i
}

/// Encode `input` as a `-pm2-` stream: one static code tree with all
/// eight literal codes at length 3 (canonical code == symbol), MTF
/// literals, and a 0 "trees unchanged" flag bit at every checkpoint
/// from the third on (the first two checkpoints read nothing because
/// the code tree carries no offset codes).
pub(crate) fn encode_pm2(input: &[u8]) -> Vec<u8> {
    let mut w = MsbWriter::new();
    w.put(0, 1); // leading dummy bit
    // Code tree: num_codes 8, min_len 3, width 1, all lengths 3
    // (entry value = len - min_len + 1 = 1).
    w.put(8, 5);
    w.put(3, 3);
    w.put(1, 3);
    for _ in 0..8 {
        w.put(1, 1);
    }
    // num_codes < 10 -> the decoder reads no offset tree at all.
    let mut hist = History::new();
    // Tree-rebuild checkpoints fire after 1024, 2048, and 4096
    // emitted bytes, then every 4096.
    let mut checkpoints = 0usize;
    let mut next = 1024usize;
    for (i, &b) in input.iter().enumerate() {
        let dist = hist.pos(b) as u32;
        let idx = vl_index(PM2_HISTORY, dist);
        w.put(idx as u32, 3); // length-3 canonical code == symbol
        w.put(dist - PM2_HISTORY[idx].offset, PM2_HISTORY[idx].bits);
        hist.update(b);
        if i + 1 == next {
            if checkpoints >= 2 {
                w.put(0, 1); // state >= 3: "trees unchanged" flag
            }
            checkpoints += 1;
            next += match checkpoints {
                1 => 1024,
                2 => 2048,
                _ => 4096,
            };
        }
    }
    w.finish()
}

/// Inverse of the decoder's `pm1_block_len` static code: 1..=216.
fn pm1_block_len_enc(w: &mut MsbWriter, n: usize) {
    if n <= 3 {
        w.put((n - 1) as u32, 2);
    } else if n <= 10 {
        w.put(3, 2);
        w.put((n - 4) as u32, 3);
    } else if n <= 24 {
        w.put(3, 2);
        w.put(7, 3);
        w.put((n - 11) as u32, 4);
    } else if n <= 88 {
        w.put(3, 2);
        w.put(7, 3);
        w.put(14, 4);
        w.put((n - 25) as u32, 6);
    } else {
        w.put(3, 2);
        w.put(7, 3);
        w.put(15, 4);
        w.put((n - 89) as u32, 7);
    }
}

/// Encode `input` as a `-pm1-` stream: byte tree 6 (the static tree
/// whose leaves cover all six history ranges), 216-literal blocks
/// with no following command, and a final short block closed by a
/// distance-0 copy the decoder accepts (its `dist < pos` check only
/// needs `pos >= 1`) but leaves un-emitted because the output is
/// already complete.
pub(crate) fn encode_pm1(input: &[u8]) -> Vec<u8> {
    const MAX_BLOCK: usize = 216;
    /// Bit paths into `PM1_BYTE_TREES[6]` for range indexes 0..=5.
    const PATHS: [(u32, u32); 6] = [
        (0b00, 2),
        (0b01, 2),
        (0b100, 3),
        (0b101, 3),
        (0b110, 3),
        (0b111, 3),
    ];
    let mut w = MsbWriter::new();
    w.put(6, 5); // byte-tree selector
    let mut hist = History::new();
    let mut i = 0usize;
    while i < input.len() {
        let n = (input.len() - i).min(MAX_BLOCK);
        w.put(1, 1); // literal-block command
        pm1_block_len_enc(&mut w, n);
        for _ in 0..n {
            let b = input[i];
            let dist = hist.pos(b) as u32;
            let idx = vl_index(PM1_BYTE_RANGES, dist);
            let (path, bits) = PATHS[idx];
            w.put(path, bits);
            w.put(
                dist - PM1_BYTE_RANGES[idx].offset,
                PM1_BYTE_RANGES[idx].bits,
            );
            hist.update(b);
            i += 1;
        }
        if n == MAX_BLOCK {
            continue; // full blocks are not followed by a copy command
        }
        // A short block is always followed by a copy command: emit a
        // range-0 copy (count 2, distance 0). `pos` is the output so
        // far; the threshold bits are only present once it grows.
        w.put(0, 1);
        if i >= 576 {
            w.put(0, 1);
        }
        if i >= 64 {
            w.put(0, 1);
        }
        w.put(0, 6); // distance 0
    }
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::lha::pmarc;

    /// Deterministic non-repeating bytes (xorshift32).
    fn noisy(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut s = 0x9e37_79b9u32;
        while v.len() < n {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            v.push((s >> 24) as u8);
        }
        v
    }

    #[test]
    fn pm2_encode_roundtrip() {
        for data in [
            b"the quick brown fox jumps over the lazy dog. ".repeat(500),
            vec![0x78u8; 300],
            noisy(500),
            Vec::new(),
            b"a".to_vec(),
        ] {
            let out = pmarc::decode(b"-pm2-", &encode_pm2(&data), data.len()).unwrap();
            assert_eq!(out, data);
        }
    }

    #[test]
    fn pm2_checkpoint_boundaries() {
        // Sizes spanning the rebuild schedule 1024/2048/4096/8192.
        for n in [1023usize, 1024, 1025, 2048, 2049, 4096, 4097, 8192, 9000] {
            let data = noisy(n);
            let out = pmarc::decode(b"-pm2-", &encode_pm2(&data), n).unwrap();
            assert_eq!(out, data);
        }
    }

    #[test]
    fn pm1_encode_roundtrip() {
        // Lengths around the 216-literal block boundary plus text.
        for data in [
            b"the quick brown fox jumps over the lazy dog. ".repeat(30),
            vec![7u8; 500],
            noisy(400),
            Vec::new(),
            b"ab".to_vec(),
            noisy(215),
            noisy(216),
            noisy(217),
            noisy(432),
            noisy(433),
        ] {
            let out = pmarc::decode(b"-pm1-", &encode_pm1(&data), data.len()).unwrap();
            assert_eq!(out, data);
        }
    }
}
