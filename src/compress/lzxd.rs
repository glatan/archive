//! LZX DELTA (LZXD) decompression, per [MS-PATCH].
//!
//! [MS-PATCH]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf
//!
//! LZXD is an LZX variant for delta compression: a caller-supplied reference
//! byte sequence is logically prepended to the subject data, and match
//! offsets may reach back into that reference data.
//!
//! Stream layout ([MS-PATCH] 2.2.1):
//! - repeated `[u16le compressed chunk size][chunk data]`; each chunk
//!   expands to exactly 32 KiB of uncompressed data except the last chunk.
//! - the compressed bitstream is a sequence of 16-bit little-endian words
//!   consumed MSB-first; the u16 chunk-size prefixes are byte-aligned and
//!   sit outside the bitstream.
//! - the first bit of the stream selects E8 call translation; when set, two
//!   u16 fields supply the 32-bit translation size.
//!
//! Blocks ([MS-PATCH] 2.3): 3-bit type (1 verbatim, 2 aligned offset,
//! 3 uncompressed) + 24-bit uncompressed block size. Blocks may span
//! chunks; a single match never spans a 32 KiB output boundary.
//!
//! Encoding support is intentionally limited to streams made of
//! uncompressed blocks (`encode`); Huffman-coded block production is out
//! of scope.

use alloc::vec::Vec;

use crate::compress::lzx;
use crate::error::Error;

/// Decode an LZXD-compressed stream.
///
/// - `input`: the compressed byte stream (chunk-size-prefixed chunks).
/// - `window_size`: sliding window size; a power of two in `2^17..=2^25`
///   ([MS-PATCH] 2.1.2), supplied out-of-band.
/// - `reference`: the exact reference bytes supplied to the compressor;
///   empty for non-delta streams.
/// - `expected_size`: uncompressed subject size. Decoding stops once this
///   many bytes have been produced.
pub fn decode(
    input: &[u8],
    window_size: usize,
    reference: &[u8],
    expected_size: usize,
) -> Result<Vec<u8>, Error> {
    lzx::decode_delta(
        input,
        window_size,
        reference,
        Some(expected_size),
        usize::MAX,
    )
}

/// Decode an LZXD stream until the compressed input is exhausted.
///
/// Blocks are self-terminating via their 24-bit uncompressed size, so a
/// well-formed stream ends exactly when its last block completes.
/// `max_output` bounds memory use on malformed or hostile input.
pub fn decode_all(
    input: &[u8],
    window_size: usize,
    reference: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    lzx::decode_delta(input, window_size, reference, None, max_output)
}

/// Encode `input` as an LZXD stream made of uncompressed blocks
/// ([MS-PATCH] 2.3.2.1). Produces no compression; useful for
/// round-tripping through `decode` and for interoperability checks.
///
/// The stream uses no reference data and no E8 translation; it decodes
/// with any valid window size.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let n = (input.len() - pos).min(lzx::CHUNK_UNCOMPRESSED);
        // Compressed chunk bytes: 2 header words + 12 (R0..R2) + data + pad.
        let csize = 4 + 12 + n + (n & 1);
        out.extend_from_slice(&(csize as u16).to_le_bytes());
        let size = n as u32;
        let (w0, w1) = if pos == 0 {
            // First chunk: 1-bit E8 flag (0) + 3-bit type + 24-bit size +
            // 4 pad bits.
            (
                (lzx::BLOCK_UNCOMPRESSED << 12) | ((size >> 12) & 0xfff),
                (size & 0xfff) << 4,
            )
        } else {
            // Later chunks: 3-bit type + 24-bit size + 5 pad bits.
            (
                (lzx::BLOCK_UNCOMPRESSED << 13) | ((size >> 11) & 0x1fff),
                (size & 0x7ff) << 5,
            )
        };
        out.extend_from_slice(&(w0 as u16).to_le_bytes());
        out.extend_from_slice(&(w1 as u16).to_le_bytes());
        for r in [1u32, 1, 1] {
            out.extend_from_slice(&r.to_le_bytes());
        }
        out.extend_from_slice(&input[pos..pos + n]);
        if n & 1 == 1 {
            out.push(0);
        }
        pos += n;
        if pos >= input.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::lzx::{Huffman, e8_reverse, num_pos_slots, slot_base_footer};
    use alloc::vec;

    const W17: usize = 1 << 17;

    /// [MS-PATCH] 3 Structure Examples: "abc" as a single uncompressed
    /// block. Exact byte stream from the specification.
    #[test]
    fn spec_example_abc() {
        #[rustfmt::skip]
        let compressed: &[u8] = &[
            0x14, 0x00, // chunk size 20
            0x00, 0x30, 0x30, 0x00, // e8=0, type=3, size=3, pad
            0x01, 0x00, 0x00, 0x00, // R0
            0x01, 0x00, 0x00, 0x00, // R1
            0x01, 0x00, 0x00, 0x00, // R2
            0x61, 0x62, 0x63, // "abc"
            0x00, // pad
        ];
        let out = decode(compressed, W17, &[], 3).unwrap();
        assert_eq!(out, b"abc");
        // The minimal encoder produces exactly this stream.
        assert_eq!(encode(b"abc"), compressed);
    }

    #[test]
    fn uncompressed_roundtrip() {
        for data in [
            b"x".as_slice(),
            b"hello world".as_slice(),
            &vec![0xabu8; 32768],
            &vec![0xcdu8; 32769],
            &vec![0xefu8; 70000],
        ] {
            let c = encode(data);
            let out = decode(&c, W17, &[], data.len()).unwrap();
            assert_eq!(&out, data);
        }
    }

    #[test]
    fn uncompressed_roundtrip_odd_last_chunk() {
        let mut data = vec![0u8; 32768 * 2 + 3];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }
        let c = encode(&data);
        assert_eq!(decode(&c, W17, &[], data.len()).unwrap(), data);
    }

    #[test]
    fn rejects_bad_window() {
        let c = encode(b"abc");
        assert!(decode(&c, 1 << 16, &[], 3).is_err());
        assert!(decode(&c, 1 << 26, &[], 3).is_err());
        assert!(decode(&c, (1 << 17) + 1, &[], 3).is_err());
    }

    #[test]
    fn accepts_window_boundaries() {
        // The legal window range is 2^17..=2^25 inclusive ([MS-PATCH] 2.1.2).
        let c = encode(b"abc");
        for window in [1usize << 17, 1 << 18, 1 << 25] {
            assert_eq!(decode(&c, window, &[], 3).unwrap(), b"abc");
        }
    }

    #[test]
    fn decode_expected_size_strict() {
        // `decode` stops exactly at expected_size: a smaller size truncates
        // mid-block, a larger size runs out of input and fails.
        let c = encode(b"abc");
        assert_eq!(decode(&c, W17, &[], 1).unwrap(), b"a");
        assert!(decode(&c, W17, &[], 4).is_err());
    }

    #[test]
    fn decode_all_max_output_boundaries() {
        // decode_all self-terminates via the block size; max_output bounds
        // the result. Exact limit passes, one below fails.
        let c = encode(b"abc");
        assert_eq!(decode_all(&c, W17, &[], 3).unwrap(), b"abc");
        assert!(decode_all(&c, W17, &[], 2).is_err());
        assert!(decode_all(&c, W17, &[], 0).is_err());
    }

    #[test]
    fn rejects_e8_flag_truncated() {
        // E8 flag set but the two u16 translation-size words are missing.
        // Chunk data is one word 0x8000: its first (MSB-first) bit is 1.
        let stream = [0x02, 0x00, 0x00, 0x80];
        assert!(decode(&stream, W17, &[], 1).is_err());
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        // Once expected_size bytes are produced, remaining input is
        // accepted unverified.
        let mut c = encode(b"abc");
        c.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decode(&c, W17, &[], 3).unwrap(), b"abc");
    }

    #[test]
    fn rejects_truncated() {
        let c = encode(b"hello world");
        for n in [0usize, 1, 2, 5, c.len() - 1] {
            assert!(decode(&c[..n], W17, &[], 11).is_err(), "n={n}");
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(decode(&[], W17, &[], 1).is_err());
        assert_eq!(decode(&[], W17, &[], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn pos_slot_table() {
        // [MS-PATCH] 2.1.6 / 2.6.2 tables.
        assert_eq!(num_pos_slots(1 << 17), 34);
        assert_eq!(num_pos_slots(1 << 18), 36);
        assert_eq!(num_pos_slots(1 << 19), 38);
        assert_eq!(num_pos_slots(1 << 20), 42);
        assert_eq!(num_pos_slots(1 << 21), 50);
        assert_eq!(num_pos_slots(1 << 22), 66);
        assert_eq!(num_pos_slots(1 << 23), 98);
        assert_eq!(num_pos_slots(1 << 24), 162);
        assert_eq!(num_pos_slots(1 << 25), 290);
        assert_eq!(slot_base_footer(0), (0, 0));
        assert_eq!(slot_base_footer(4), (4, 1));
        assert_eq!(slot_base_footer(14), (128, 6));
        assert_eq!(slot_base_footer(33), (98304, 15));
        assert_eq!(slot_base_footer(35), (196608, 16));
        assert_eq!(slot_base_footer(36), (262144, 17));
        assert_eq!(slot_base_footer(42), (1048576, 17));
        assert_eq!(slot_base_footer(289), (33423360, 17));
    }

    #[test]
    fn huffman_decode() {
        // Lens: a=1, b=2, c=3, d=3 (complete tree).
        let h = Huffman::build(&[1, 2, 3, 3]).unwrap();
        assert_eq!(h.counts[1], 1);
        assert_eq!(h.counts[2], 1);
        assert_eq!(h.counts[3], 2);
        assert_eq!(h.symbols, vec![0, 1, 2, 3]);
        // Over-subscribed tree rejected.
        assert!(Huffman::build(&[1, 1, 1]).is_err());
    }

    #[test]
    fn e8_reverse_basic() {
        // value 0 at 0xE8+1 with cur=0 → displacement 0 → unchanged.
        let mut chunk = vec![0xaau8; 16];
        chunk[0] = 0xe8;
        chunk[1] = 0;
        chunk[2] = 0;
        chunk[3] = 0;
        chunk[4] = 0;
        e8_reverse(&mut chunk, 0, 1000);
        assert_eq!(&chunk[1..5], &[0, 0, 0, 0]);
        // value 500 at pos 0 → displacement = 500 - 0 = 500.
        let mut chunk = vec![0xe8u8, 0xf4, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        e8_reverse(&mut chunk, 0, 1000);
        assert_eq!(&chunk[1..5], &[0xf4, 0x01, 0, 0]);
    }

    #[test]
    fn huffman_accepts_incomplete_tree() {
        // Under-subscribed lens leave unassigned code space but are legal:
        // the libmspack-validated vectors exercise real incomplete trees.
        // Only oversubscription is a build-time error.
        assert!(Huffman::build(&[2, 2]).is_ok());
        assert!(Huffman::build(&[1]).is_ok());
        assert!(Huffman::build(&[0; 8]).is_ok()); // empty tree builds; usage is checked later
        // Length out of range still rejected.
        assert!(Huffman::build(&[17, 1]).is_err());
    }

    #[test]
    fn rejects_bad_chunk_layout() {
        // Chunk prefix declaring a zero-size chunk.
        assert!(decode(&[0x00, 0x00], W17, &[], 1).is_err());
        // Declared chunk size exceeds the data actually present.
        assert!(decode(&[0x05, 0x00, 0xaa], W17, &[], 1).is_err());
        // A lone byte cannot even hold the 2-byte size prefix.
        assert!(decode(&[0x05], W17, &[], 1).is_err());
    }
}
