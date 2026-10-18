//! LZNT1 compression — MS-XCA §2.5.
//!
//! The stream is a sequence of chunks. Each chunk starts with a 16-bit
//! little-endian header: bit 15 marks a compressed chunk, bits 14:12 carry
//! the signature value 3, and bits 11:0 hold the chunk size minus three
//! (header included). A zero header terminates the buffer.
//!
//! A compressed chunk is a series of flag groups: one flag byte followed by
//! up to 8 data elements, where a set flag bit selects a two-byte
//! "compressed word" and a clear bit selects a literal byte. The layout of
//! a compressed word depends on the number of uncompressed bytes already
//! processed within the chunk: with `U` processed, `M` is the largest value
//! in `4..=12` such that `2^(M-1) < U` (or 4 if none); the word holds an
//! `M`-bit displacement minus one in the high bits and a `(16-M)`-bit match
//! length minus three in the low bits.

use alloc::vec::Vec;

use crate::error::Error;

use super::lz77::MatchTable;

/// Maximum uncompressed bytes emitted per chunk (window is 2^12).
const CHUNK_UNCOMPRESSED_MAX: usize = 4096;
/// Maximum match distance.
const MAX_OFFSET: usize = 1 << 12;
const MIN_MATCH: usize = 3;
const CHUNK_SIGNATURE: u16 = 3;

/// Number of displacement bits in a compressed word at uncompressed
/// position `u` within the current chunk.
fn displacement_bits(u: usize) -> usize {
    let mut m = 4usize;
    for cand in (4..=12usize).rev() {
        if (1usize << (cand - 1)) < u {
            m = cand;
            break;
        }
    }
    m
}

/// Decode an LZNT1 stream.
///
/// The compressed size must be known (i.e. `input` must contain exactly one
/// compressed buffer): the end-of-buffer marker is optional per spec.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZNT1 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    loop {
        if pos == input.len() {
            break; // buffer without an End_of_buffer marker
        }
        if pos + 2 > input.len() {
            return Err(Error::InvalidData("lznt1: truncated chunk header"));
        }
        let header = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap());
        pos += 2;
        if header == 0 {
            break; // End_of_buffer
        }
        if (header >> 12) & 0x7 != CHUNK_SIGNATURE {
            return Err(Error::InvalidData("lznt1: bad chunk signature"));
        }
        let chunk_size = (header & 0x0fff) as usize + 3;
        let payload = chunk_size - 2;
        if pos + payload > input.len() {
            return Err(Error::InvalidData("lznt1: truncated chunk"));
        }
        let end = pos + payload;
        if header & 0x8000 == 0 {
            out.extend_from_slice(&input[pos..end]);
            if out.len() > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            pos = end;
            continue;
        }

        // Compressed chunk: flag groups until the chunk input is consumed.
        let mut u = 0usize; // uncompressed bytes processed in this chunk
        while pos < end {
            let flag = input[pos];
            pos += 1;
            for bit in 0..8 {
                if pos >= end {
                    break;
                }
                if flag & (1 << bit) == 0 {
                    out.push(input[pos]);
                    pos += 1;
                    u += 1;
                } else {
                    if pos + 2 > end {
                        return Err(Error::InvalidData("lznt1: truncated compressed word"));
                    }
                    let word = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap()) as usize;
                    pos += 2;
                    let m = displacement_bits(u);
                    let l = 16 - m;
                    let len = (word & ((1 << l) - 1)) + 3;
                    let disp = (word >> l) + 1;
                    if disp > u || disp > out.len() {
                        return Err(Error::InvalidData("lznt1: displacement before start"));
                    }
                    if out.len() + len > max_output {
                        return Err(Error::OutputLimitExceeded { limit: max_output });
                    }
                    crate::compress::match_ops::copy_match(&mut out, disp, len)
                        .map_err(|_| Error::InvalidData("lznt1: displacement before start"))?;
                    u += len;
                }
                if out.len() > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
            }
        }
        if pos != end {
            return Err(Error::InvalidData("lznt1: chunk size mismatch"));
        }
    }
    Ok(out)
}

/// Encode data as an LZNT1 stream.
///
/// Input is split into chunks of at most 4096 uncompressed bytes. Chunks
/// that do not compress below their raw size are emitted as uncompressed
/// chunks. The buffer always ends with an `End_of_buffer` marker.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() + input.len() / 64 + 8);
    let mut pos = 0usize;

    while pos < input.len() {
        let take = (input.len() - pos).min(CHUNK_UNCOMPRESSED_MAX);
        let chunk = &input[pos..pos + take];
        let compressed = encode_chunk(chunk);

        // +2 for the header; use the uncompressed form when compression did
        // not save space.
        if compressed.len() + 2 >= chunk.len() + 2 {
            let header = ((chunk.len() as u16 - 1) & 0x0fff) | (CHUNK_SIGNATURE << 12);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(chunk);
        } else {
            // field = total chunk size (header + payload) minus three.
            let header =
                (((compressed.len() + 2 - 3) as u16) & 0x0fff) | (CHUNK_SIGNATURE << 12) | 0x8000;
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(&compressed);
        }
        pos += take;
    }

    out.extend_from_slice(&0u16.to_le_bytes()); // End_of_buffer
    out
}

/// Compress one chunk of at most [`CHUNK_UNCOMPRESSED_MAX`] bytes.
fn encode_chunk(chunk: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(chunk.len());
    let mut table = MatchTable::new(chunk);
    let mut flag_pos = 0usize;
    let mut flag = 0u8;
    let mut elem = 0u8;
    out.push(0); // first flag byte slot
    let mut pos = 0usize;

    while pos < chunk.len() {
        let u = pos; // uncompressed bytes already processed in this chunk
        let m_bits = displacement_bits(u);
        let l_bits = 16 - m_bits;
        let max_len = ((1usize << l_bits) - 1) + 3;

        let found = if pos + MIN_MATCH <= chunk.len() {
            table.find(chunk, pos, MAX_OFFSET.min(u))
        } else {
            None
        };
        // Cap the match length at what the current L field can encode.
        let found = found.map(|(d, l)| (d, l.min(max_len)));
        let found = found.filter(|&(d, l)| l >= MIN_MATCH && d - 1 < (1 << m_bits));

        match found {
            Some((disp, len)) => {
                let word = (((disp - 1) << l_bits) | (len - 3)) as u16;
                out.extend_from_slice(&word.to_le_bytes());
                flag |= 1 << elem;
                pos += len;
            }
            None => {
                out.push(chunk[pos]);
                pos += 1;
            }
        }
        elem += 1;
        if elem == 8 {
            out[flag_pos] = flag;
            flag = 0;
            elem = 0;
            flag_pos = out.len();
            out.push(0);
        }
    }
    if elem > 0 {
        out[flag_pos] = flag;
    } else {
        // An empty trailing flag byte slot was reserved; drop it.
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn roundtrip_various() {
        rt(b"");
        rt(b"a");
        rt(b"abc");
        rt(&[0u8; 5000]);
        rt(b"abcabcabcabcabcabcabcabcabcabcabc");
        let mut big = Vec::new();
        for i in 0..10000u32 {
            big.extend_from_slice(&i.to_le_bytes());
        }
        rt(&big);
        // Many chunks with repetitions across chunk boundaries.
        let mut rep = Vec::new();
        for _ in 0..50 {
            rep.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt(&rep);
    }

    #[test]
    fn displacement_bit_schedule() {
        assert_eq!(displacement_bits(0), 4);
        assert_eq!(displacement_bits(1), 4);
        assert_eq!(displacement_bits(9), 4);
        assert_eq!(displacement_bits(17), 5);
        assert_eq!(displacement_bits(33), 6);
        assert_eq!(displacement_bits(4096), 12);
        assert_eq!(displacement_bits(10000), 12);
    }

    #[test]
    fn uncompressed_chunk_roundtrip() {
        // Incompressible data must come back byte-identical via the
        // uncompressed-chunk path.
        let mut data = Vec::new();
        let mut x = 0x12345678u32;
        for _ in 0..3000 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((x >> 24) as u8);
        }
        rt(&data);
        // Verify at least one uncompressed chunk was emitted.
        let hdr = u16::from_le_bytes(encode(&data)[..2].try_into().unwrap());
        assert_eq!(hdr & 0x8000, 0);
    }

    #[test]
    fn end_of_buffer_marker() {
        let enc = encode(b"data");
        assert_eq!(&enc[enc.len() - 2..], &[0, 0]);
    }

    #[test]
    fn rejects_bad_signature() {
        // sig != 3 must be rejected.
        let input = [0x01, 0x10, b'a'];
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_displacement_before_start() {
        // MS-XCA §2.5: a match may not reference more bytes than have
        // been produced. First element of the chunk is a compressed
        // word (flag bit0=1); any displacement at u=0 is before start.
        // Chunk: payload = flag(1B) + word(2B) = 3B -> size field = 5-3 = 2.
        let input = [0x02, 0xB0, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(decode(&input), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_truncated_chunk() {
        let enc = encode(b"hello world hello world hello world");
        let cut = enc.len() - 3;
        assert!(decode(&enc[..cut]).is_err());
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'z'; 9000];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
    }
}
