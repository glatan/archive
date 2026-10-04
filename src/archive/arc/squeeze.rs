//! ARC method 4 ("squeezed") — RLE90 + static Huffman (CP/M `SQ` codec).
//!
//! Wire format of the member payload:
//!
//! ```text
//! +-----------+========================+=====================+
//! | numnodes  | node table (4·N bytes) | Huffman bitstream   |
//! | (u16 LE)  | 2× i16 LE per node     | (LSB-first)         |
//! +-----------+========================+=====================+
//! ```
//!
//! Each node holds `(left, right)` children. A non-negative child is
//! the index of another node (walk starts at node 0, `0`-bit = left,
//! `1`-bit = right); a negative child `c` is a leaf for value
//! `-(c) - 1` where 0..=255 are literal bytes and 256 is the
//! end-of-stream marker (`SPEOF`). `numnodes == 0` is an empty
//! stream. The Huffman-decoded byte sequence is an RLE90 stream
//! (same packing as method 3) that expands to the member data.
//!
//! De-facto format references for the CP/M `SQ`/`USQ` lineage:
//! XADMaster `XADSqueezeHandle` (observation only) and compcol
//! `arc_squeeze` (MIT — wire-format documentation and decoder
//! structure adapted; the encoder is crate-original). nomarch is a
//! test-time oracle only, not an implementation reference.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::rle90;

/// End-of-stream Huffman symbol.
const SPEOF: u16 = 256;
/// Number of Huffman symbols (256 bytes + SPEOF).
const NUM_SYMBOLS: usize = 257;
/// A full binary tree over [`NUM_SYMBOLS`] leaves has at most
/// `2 * NUM_SYMBOLS - 1` nodes; bound the header table.
const MAX_NODES: usize = 2 * NUM_SYMBOLS;

/// Decode a squeezed member payload to exactly `original_size` bytes.
pub(crate) fn decode(packed: &[u8], original_size: usize) -> Result<Vec<u8>, Error> {
    if packed.len() < 2 {
        return Err(Error::InvalidData("arc: truncated squeeze header"));
    }
    let numnodes = usize::from(u16::from_le_bytes([packed[0], packed[1]]));
    if numnodes > MAX_NODES {
        return Err(Error::InvalidData("arc: squeeze node count out of range"));
    }
    if numnodes == 0 {
        // Empty stream: no Huffman data at all.
        return rle90::decode(&[], original_size);
    }
    if packed.len() < 2 + 4 * numnodes {
        return Err(Error::InvalidData("arc: truncated squeeze node table"));
    }

    let mut table = Vec::with_capacity(numnodes);
    for i in 0..numnodes {
        let o = 2 + 4 * i;
        let l = i16::from_le_bytes([packed[o], packed[o + 1]]);
        let r = i16::from_le_bytes([packed[o + 2], packed[o + 3]]);
        table.push((l, r));
    }
    for &(l, r) in &table {
        for child in [l, r] {
            if child >= 0 {
                if child as usize >= numnodes {
                    return Err(Error::InvalidData("arc: bad squeeze node index"));
                }
            } else if (-(child as i32) - 1) > SPEOF as i32 {
                return Err(Error::InvalidData("arc: bad squeeze leaf value"));
            }
        }
    }

    // Walk the Huffman tree over the LSB-first bitstream and feed each
    // decoded byte through the RLE90 stage, capped at original_size.
    let bits = &packed[2 + 4 * numnodes..];
    let mut out = Vec::with_capacity(original_size);
    let mut rle_last: Option<u8> = None;
    let mut rle_pending = false;
    let mut emit = |out: &mut Vec<u8>, b: u8| -> Result<(), Error> {
        if rle_pending {
            rle_pending = false;
            if b == 0 {
                out.push(0x90);
            } else {
                let &last = rle_last
                    .as_ref()
                    .ok_or(Error::InvalidData("arc: rle90 run without literal"))?;
                out.resize(out.len() + usize::from(b) - 1, last);
            }
        } else if b == 0x90 {
            rle_pending = true;
            return Ok(());
        } else {
            out.push(b);
        }
        rle_last = Some(*out.last().unwrap_or(&0));
        if out.len() > original_size {
            return Err(Error::InvalidData("arc: squeeze expansion exceeds size"));
        }
        Ok(())
    };

    let mut node = 0usize;
    let mut saw_eos = false;
    'bits: for &byte in bits {
        for k in 0..8 {
            let bit = (byte >> k) & 1;
            let (l, r) = table[node];
            let next = if bit == 0 { l } else { r };
            if next < 0 {
                let leaf = (-(next as i32) - 1) as u16;
                node = 0;
                if leaf == SPEOF {
                    saw_eos = true;
                    break 'bits;
                }
                emit(&mut out, leaf as u8)?;
            } else {
                node = next as usize;
            }
        }
    }

    if !saw_eos && out.len() != original_size {
        return Err(Error::InvalidData("arc: truncated squeeze stream"));
    }
    if rle_pending {
        return Err(Error::InvalidData("arc: truncated rle90 run"));
    }
    if out.len() != original_size {
        return Err(Error::InvalidData("arc: squeeze size mismatch"));
    }
    Ok(out)
}

/// Encode data as a squeezed member payload (RLE90 + static Huffman).
pub(crate) fn encode(data: &[u8]) -> Vec<u8> {
    let rle = rle90::encode(data);

    // Frequency table over the RLE stream plus the EOS symbol.
    let mut freq = [0u32; NUM_SYMBOLS];
    for &b in &rle {
        freq[b as usize] += 1;
    }
    freq[SPEOF as usize] = 1;

    // An empty RLE stream yields the numnodes==0 empty-stream encoding.
    if rle.is_empty() {
        return vec![0, 0];
    }
    // Symbols present: every distinct RLE byte plus SPEOF, so at least
    // two leaves always exist.
    let syms: Vec<u16> = (0..NUM_SYMBOLS as u16)
        .filter(|&s| freq[s as usize] > 0)
        .collect();

    // Build the Huffman tree bottom-up. Each internal node records its
    // children as either a node index (>=0) or a leaf (-(sym+1)).
    let mut nodes: Vec<(i16, i16)> = Vec::new();
    // Work list of (freq, ref) where ref is i32: >=0 node index, <0 leaf.
    let mut heap: Vec<(u64, i32)> = syms
        .iter()
        .map(|&s| (freq[s as usize] as u64, -(s as i32) - 1))
        .collect();
    // Order by (freq, insertion-order tie-break via ref) — simplest is a
    // repeated min-extraction; NUM_SYMBOLS is tiny.
    while heap.len() > 1 {
        heap.sort_by_key(|&(f, r)| (f, r));
        let (fa, a) = heap.remove(0);
        let (fb, b) = heap.remove(0);
        let idx = nodes.len() as i32;
        nodes.push((a as i16, b as i16));
        heap.push((fa + fb, idx));
    }
    let root = heap[0].1;

    // Re-serialise the node table so the root lands at index 0. Build a
    // remap by BFS from the root.
    let mut remap = alloc::collections::BTreeMap::new();
    let mut order = Vec::new();
    let mut queue = alloc::collections::VecDeque::new();
    queue.push_back(root);
    while let Some(idx) = queue.pop_front() {
        if idx < 0 || remap.contains_key(&idx) {
            continue;
        }
        let new_idx = order.len() as i32;
        remap.insert(idx, new_idx);
        order.push(idx);
        let (l, r) = nodes[idx as usize];
        if l >= 0 {
            queue.push_back(l as i32);
        }
        if r >= 0 {
            queue.push_back(r as i32);
        }
    }
    let table: Vec<(i16, i16)> = order
        .iter()
        .map(|&old| {
            let (l, r) = nodes[old as usize];
            (
                if l >= 0 { remap[&(l as i32)] as i16 } else { l },
                if r >= 0 { remap[&(r as i32)] as i16 } else { r },
            )
        })
        .collect();

    // Assign per-symbol codes: bit i of `bits` is the direction taken at
    // depth i (0 = left, 1 = right), emitted LSB-first.
    let mut codes = [(0u32, 0u8); NUM_SYMBOLS];
    fn walk(
        table: &[(i16, i16)],
        node: i16,
        bits: u32,
        len: u8,
        codes: &mut [(u32, u8); NUM_SYMBOLS],
    ) {
        let (l, r) = table[node as usize];
        for (child, dir) in [(l, 0u32), (r, 1)] {
            if child < 0 {
                let sym = (-(child as i32) - 1) as usize;
                codes[sym] = (bits | (dir << len), len + 1);
            } else {
                walk(table, child, bits | (dir << len), len + 1, codes);
            }
        }
    }
    walk(&table, 0, 0, 0, &mut codes);

    // Serialise: numnodes + node table + bitstream.
    let mut out = Vec::new();
    let n = table.len() as u16;
    out.extend_from_slice(&n.to_le_bytes());
    for &(l, r) in &table {
        out.extend_from_slice(&l.to_le_bytes());
        out.extend_from_slice(&r.to_le_bytes());
    }

    let mut bit_acc: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut emit_bits = |bits: u32, len: u8, out: &mut Vec<u8>| {
        bit_acc |= bits << bit_count;
        bit_count += len;
        while bit_count >= 8 {
            out.push(bit_acc as u8);
            bit_acc >>= 8;
            bit_count -= 8;
        }
    };
    for &b in &rle {
        let (bits, len) = codes[b as usize];
        emit_bits(bits, len, &mut out);
    }
    let (bits, len) = codes[SPEOF as usize];
    emit_bits(bits, len, &mut out);
    if bit_count > 0 {
        out.push(bit_acc as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for data in [
            &b""[..],
            b"a",
            b"hello squeezed world hello squeezed world",
            &[0x90, 0x90, 0x90],
            &[0u8; 1000],
            &(0u8..=255).cycle().take(4096).collect::<Vec<u8>>(),
        ] {
            let packed = encode(data);
            let out = decode(&packed, data.len()).unwrap();
            assert_eq!(out, data);
        }
    }

    #[test]
    fn empty_stream() {
        assert_eq!(encode(b""), vec![0, 0]);
        assert_eq!(decode(&[0, 0], 0).unwrap(), Vec::<u8>::new());
        assert!(decode(&[0, 0], 5).is_err());
    }

    #[test]
    fn rejects_bad_table() {
        // numnodes larger than bound.
        assert!(decode(&[0xFF, 0xFF, 0, 0], 10).is_err());
        // Truncated node table.
        let mut p = vec![2u8, 0];
        p.extend_from_slice(&[0; 3]);
        assert!(decode(&p, 10).is_err());
        // Out-of-range child index.
        let mut p = vec![1u8, 0];
        p.extend_from_slice(&5i16.to_le_bytes());
        p.extend_from_slice(&(-1i16).to_le_bytes());
        p.push(0);
        assert!(decode(&p, 10).is_err());
        // Leaf value > 256.
        let mut p = vec![1u8, 0];
        p.extend_from_slice(&(-300i16).to_le_bytes());
        p.extend_from_slice(&(-1i16).to_le_bytes());
        p.push(0);
        assert!(decode(&p, 10).is_err());
    }

    #[test]
    fn rejects_truncated_stream() {
        let data = b"some data that will not fit in one symbol some data";
        let packed = encode(data);
        // Cutting inside or right after the node table must fail.
        let numnodes = usize::from(u16::from_le_bytes([packed[0], packed[1]]));
        let table_end = 2 + 4 * numnodes;
        assert!(decode(&packed[..table_end], data.len()).is_err());
        // A single bitstream byte cannot satisfy the declared size.
        assert!(decode(&packed[..table_end + 1], data.len()).is_err());
    }
}
