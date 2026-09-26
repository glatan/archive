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

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Uncompressed bytes per stream chunk ([MS-PATCH] 2.2.1).
const CHUNK_UNCOMPRESSED: usize = 32768;
/// Main-tree literal alphabet size.
const NUM_LITERALS: usize = 256;
/// Length-tree element count ([MS-PATCH] 2.4).
const LENGTH_TREE_ELEMENTS: usize = 249;
/// Pretree element count ([MS-PATCH] 2.5).
const PRETREE_ELEMENTS: usize = 20;
/// Aligned-offset tree element count ([MS-PATCH] 2.3.2.3).
const ALIGNED_TREE_ELEMENTS: usize = 8;
/// Maximum Huffman path length.
const MAX_CODE_LENGTH: usize = 16;

const BLOCK_VERBATIM: u32 = 1;
const BLOCK_ALIGNED: u32 = 2;
const BLOCK_UNCOMPRESSED: u32 = 3;

/// Byte-wise reader over the chunked container: u16 little-endian
/// compressed-size prefixes separate per-chunk data segments.
struct ChunkedSource<'a> {
    data: &'a [u8],
    /// Next byte index to consume.
    pos: usize,
    /// End index of the current chunk's compressed data.
    limit: usize,
    /// Whether a chunk segment is currently open. A bitstream word fetch
    /// may only hop to the next chunk between output chunks; raw byte reads
    /// (uncompressed block payload) may hop freely.
    open: bool,
}

impl<'a> ChunkedSource<'a> {
    fn new(data: &'a [u8]) -> Self {
        ChunkedSource {
            data,
            pos: 0,
            limit: 0,
            open: false,
        }
    }

    fn load_chunk(&mut self) -> Result<(), Error> {
        self.pos = self.limit;
        if self.pos + 2 > self.data.len() {
            return Err(Error::InvalidData("lzxd: truncated chunk prefix"));
        }
        let csize = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
        if csize == 0 {
            return Err(Error::InvalidData("lzxd: empty chunk"));
        }
        self.pos += 2;
        self.limit = self.pos + csize;
        if self.limit > self.data.len() {
            return Err(Error::InvalidData("lzxd: truncated chunk data"));
        }
        self.open = true;
        Ok(())
    }

    /// Next bitstream byte: hops to the next chunk only when no chunk is
    /// open (i.e., immediately after `finish_chunk` or at stream start).
    fn stream_byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.limit {
            if self.open {
                return Err(Error::InvalidData("lzxd: element straddles chunk"));
            }
            self.load_chunk()?;
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Next raw byte (uncompressed-block payload, R0..R2 fields): may hop
    /// chunk boundaries mid-block.
    fn raw_byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.limit {
            self.load_chunk()?;
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Discard the unconsumed remainder of the current chunk segment.
    fn finish_chunk(&mut self) {
        self.pos = self.limit;
        self.open = false;
    }
}

/// MSB-first bitreader over little-endian 16-bit words ([MS-PATCH] 2.1.1).
/// Word fetches are bounded to the current chunk segment so that buffered
/// bits left over at a chunk boundary are pure zero padding.
struct BitReader<'a> {
    src: ChunkedSource<'a>,
    buf: u64,
    cnt: u32,
    /// Pending high byte of a bitstream word returned as raw bytes.
    pending: Option<u8>,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            src: ChunkedSource::new(data),
            buf: 0,
            cnt: 0,
            pending: None,
        }
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        while self.cnt < n {
            let lo = self.src.stream_byte()? as u64;
            let hi = self.src.stream_byte()? as u64;
            self.buf = (self.buf << 16) | (hi << 8) | lo;
            self.cnt += 16;
        }
        self.cnt -= n;
        let v = (self.buf >> self.cnt) & ((1u64 << n) - 1);
        self.buf &= (1u64 << self.cnt) - 1;
        Ok(v as u32)
    }

    /// Discard buffered padding bits and the unfetched tail of the chunk.
    /// Buffered bits here are the zero padding written by the encoder
    /// (fetches never overtake the chunk's written data).
    fn finish_chunk(&mut self) {
        self.buf = 0;
        self.cnt = 0;
        self.pending = None;
        self.src.finish_chunk();
    }

    /// True when no more compressed input remains. Any buffered bits at
    /// this point are stream-tail padding.
    fn at_end(&self) -> bool {
        self.src.pos >= self.src.limit && self.src.pos >= self.src.data.len()
    }

    /// Discard bits up to the next 16-bit boundary (the 1..=16 bits of
    /// padding that precede an uncompressed block's byte stream).
    fn align_word(&mut self) -> Result<(), Error> {
        let pad = self.cnt % 16;
        if pad != 0 && self.bits(pad)? != 0 {
            return Err(Error::InvalidData("lzxd: nonzero alignment padding"));
        }
        Ok(())
    }

    /// Read one byte from the byte stream ([MS-PATCH] 2.3.2.1). Buffered
    /// bitstream words are drained first in little-endian order.
    fn raw_byte(&mut self) -> Result<u8, Error> {
        if let Some(b) = self.pending.take() {
            return Ok(b);
        }
        if self.cnt >= 16 {
            self.cnt -= 16;
            let w = ((self.buf >> self.cnt) & 0xffff) as u16;
            self.buf &= (1u64 << self.cnt) - 1;
            self.pending = Some((w >> 8) as u8);
            return Ok((w & 0xff) as u8);
        }
        debug_assert_eq!(self.cnt, 0);
        self.src.raw_byte()
    }

    fn raw_u32(&mut self) -> Result<u32, Error> {
        let b0 = self.raw_byte()? as u32;
        let b1 = self.raw_byte()? as u32;
        let b2 = self.raw_byte()? as u32;
        let b3 = self.raw_byte()? as u32;
        Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
    }
}

/// Canonical Huffman decoder over path lengths ([MS-PATCH] 2.4/2.5).
struct Huffman {
    /// Number of symbols with each code length, index 1..=16.
    counts: [u16; MAX_CODE_LENGTH + 1],
    /// Symbols sorted by (code length, symbol index).
    symbols: Vec<u16>,
}

impl Huffman {
    fn build(lens: &[u8]) -> Result<Huffman, Error> {
        let mut counts = [0u16; MAX_CODE_LENGTH + 1];
        for &l in lens {
            if l as usize > MAX_CODE_LENGTH {
                return Err(Error::InvalidData("lzxd: path length out of range"));
            }
            if l != 0 {
                counts[l as usize] += 1;
            }
        }
        // Kraft check: codes must not oversubscribe the tree.
        let mut left: i64 = 1;
        for &count in counts.iter().skip(1) {
            left <<= 1;
            left -= count as i64;
            if left < 0 {
                return Err(Error::InvalidData("lzxd: over-subscribed huffman tree"));
            }
        }
        let mut symbols = Vec::with_capacity(lens.len());
        for l in 1..=MAX_CODE_LENGTH {
            for (sym, &sl) in lens.iter().enumerate() {
                if sl as usize == l {
                    symbols.push(sym as u16);
                }
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    fn decode(&self, r: &mut BitReader) -> Result<u16, Error> {
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: u32 = 0;
        for len in 1..=MAX_CODE_LENGTH {
            code = (code << 1) | r.bits(1)?;
            let count = self.counts[len] as u32;
            if code < first + count {
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
        }
        Err(Error::InvalidData("lzxd: huffman code out of range"))
    }
}

/// Number of position slots for a window size ([MS-PATCH] 2.1.6).
fn num_pos_slots(window_size: usize) -> usize {
    debug_assert!(window_size.is_power_of_two());
    if window_size <= (1 << 19) {
        window_size.trailing_zeros() as usize * 2
    } else {
        (window_size >> 17) + 34
    }
}

/// Position-slot base position and footer bit count ([MS-PATCH] 2.6.2).
fn slot_base_footer(slot: usize) -> (u32, u32) {
    if slot < 4 {
        (slot as u32, 0)
    } else if slot < 36 {
        let footer = (slot >> 1) - 1;
        (((2 + (slot & 1)) << footer) as u32, footer as u32)
    } else {
        (((slot - 34) << 17) as u32, 17)
    }
}

/// Decoder state: bitstream plus tree path lengths which persist across
/// blocks via delta encoding ([MS-PATCH] 2.5).
struct Decoder<'a> {
    bits: BitReader<'a>,
    window_size: usize,
    r: [u32; 3],
    main_lens: Vec<u8>,
    length_lens: Vec<u8>,
    /// Current block type and uncompressed bytes left to produce.
    block_type: u32,
    block_left: u64,
    block_size: u64,
    main_tree: Option<Huffman>,
    length_tree: Option<Huffman>,
    aligned_tree: Option<Huffman>,
}

impl<'a> Decoder<'a> {
    /// Decode a pretree ([MS-PATCH] 2.5: 20 elements, 4 bits each) then use
    /// it to decode the delta path lengths of `lens` in place.
    fn read_tree(bits: &mut BitReader, lens: &mut [u8]) -> Result<(), Error> {
        let mut pretree_lens = [0u8; PRETREE_ELEMENTS];
        for l in pretree_lens.iter_mut() {
            *l = bits.bits(4)? as u8;
        }
        let pretree = Huffman::build(&pretree_lens)?;
        let mut i = 0usize;
        while i < lens.len() {
            let code = pretree.decode(bits)? as usize;
            match code {
                0..=16 => {
                    lens[i] = ((lens[i] as u32 + 17 - code as u32) % 17) as u8;
                    i += 1;
                }
                17 => {
                    let z = 4 + bits.bits(4)? as usize;
                    if i + z > lens.len() {
                        return Err(Error::InvalidData("lzxd: tree run past end"));
                    }
                    lens[i..i + z].fill(0);
                    i += z;
                }
                18 => {
                    let z = 20 + bits.bits(5)? as usize;
                    if i + z > lens.len() {
                        return Err(Error::InvalidData("lzxd: tree run past end"));
                    }
                    lens[i..i + z].fill(0);
                    i += z;
                }
                _ => {
                    let same = 4 + bits.bits(1)? as usize;
                    let code = pretree.decode(bits)? as usize;
                    if code > 16 {
                        return Err(Error::InvalidData("lzxd: bad repeated tree code"));
                    }
                    let v = ((lens[i] as u32 + 17 - code as u32) % 17) as u8;
                    if i + same > lens.len() {
                        return Err(Error::InvalidData("lzxd: tree run past end"));
                    }
                    lens[i..i + same].fill(v);
                    i += same;
                }
            }
        }
        Ok(())
    }

    fn read_block_header(&mut self) -> Result<(), Error> {
        self.block_type = self.bits.bits(3)?;
        if !matches!(
            self.block_type,
            BLOCK_VERBATIM | BLOCK_ALIGNED | BLOCK_UNCOMPRESSED
        ) {
            return Err(Error::InvalidData("lzxd: invalid block type"));
        }
        self.block_left = self.bits.bits(24)? as u64;
        self.block_size = self.block_left;
        match self.block_type {
            BLOCK_UNCOMPRESSED => {
                self.bits.align_word()?;
                self.r[0] = self.bits.raw_u32()?;
                self.r[1] = self.bits.raw_u32()?;
                self.r[2] = self.bits.raw_u32()?;
            }
            BLOCK_VERBATIM | BLOCK_ALIGNED => {
                if self.block_type == BLOCK_ALIGNED {
                    let mut lens = [0u8; ALIGNED_TREE_ELEMENTS];
                    for l in lens.iter_mut() {
                        *l = self.bits.bits(3)? as u8;
                    }
                    self.aligned_tree = Some(Huffman::build(&lens)?);
                }
                // The main tree is encoded in two halves (first 256 literal
                // elements, then the match elements), each with a pretree.
                let (first, rest) = self.main_lens.split_at_mut(NUM_LITERALS);
                Self::read_tree(&mut self.bits, first)?;
                Self::read_tree(&mut self.bits, rest)?;
                Self::read_tree(&mut self.bits, &mut self.length_lens)?;
                self.main_tree = Some(Huffman::build(&self.main_lens)?);
                self.length_tree = Some(Huffman::build(&self.length_lens)?);
                if self.main_tree.as_ref().unwrap().is_empty() {
                    return Err(Error::InvalidData("lzxd: empty main tree"));
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    /// Decode one verbatim/aligned element, appending to `out`.
    fn decode_element(&mut self, reference: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let main = self.main_tree.as_ref().unwrap();
        let elem = main.decode(&mut self.bits)? as usize;
        if elem < NUM_LITERALS {
            out.push(elem as u8);
            return Ok(());
        }
        let len_pos = elem - NUM_LITERALS;
        let length_header = len_pos & 7;
        let pos_slot = len_pos >> 3;

        let mut match_len = if length_header < 7 {
            length_header + 2
        } else {
            let lt = self.length_tree.as_ref().unwrap();
            if lt.is_empty() {
                return Err(Error::InvalidData("lzxd: missing length tree"));
            }
            9 + lt.decode(&mut self.bits)? as usize
        };

        let match_offset: u32 = match pos_slot {
            0 => self.r[0],
            1 => {
                self.r.swap(0, 1);
                self.r[0]
            }
            2 => {
                self.r.swap(0, 2);
                self.r[0]
            }
            _ => {
                let (base, footer_bits) = slot_base_footer(pos_slot);
                let footer = if self.block_type == BLOCK_ALIGNED && footer_bits > 3 {
                    let verbatim = self.bits.bits(footer_bits - 3)? << 3;
                    let at = self.aligned_tree.as_ref().unwrap();
                    if at.is_empty() {
                        return Err(Error::InvalidData("lzxd: missing aligned tree"));
                    }
                    verbatim + at.decode(&mut self.bits)? as u32
                } else {
                    self.bits.bits(footer_bits)?
                };
                let real = base
                    .checked_add(footer)
                    .and_then(|f| f.checked_sub(2))
                    .ok_or(Error::InvalidData("lzxd: offset underflow"))?;
                if real == 0 || real as usize > self.window_size {
                    return Err(Error::InvalidData("lzxd: match offset out of range"));
                }
                self.r[2] = self.r[1];
                self.r[1] = self.r[0];
                self.r[0] = real;
                real
            }
        };

        if match_len == 257 {
            // Extra length field ([MS-PATCH] 2.6.6).
            let extra = if self.bits.bits(1)? != 0 {
                if self.bits.bits(1)? != 0 {
                    if self.bits.bits(1)? != 0 {
                        self.bits.bits(15)?
                    } else {
                        self.bits.bits(12)? + 1024 + 256
                    }
                } else {
                    self.bits.bits(10)? + 256
                }
            } else {
                self.bits.bits(8)?
            };
            match_len = 257 + extra as usize;
        }
        if match_len > 32768 {
            return Err(Error::InvalidData("lzxd: match length out of range"));
        }

        let offset = match_offset as usize;
        let cur = reference.len() + out.len();
        if offset > cur {
            return Err(Error::InvalidData("lzxd: match offset before start"));
        }
        let start = cur - offset;
        for i in 0..match_len {
            let b = window_byte(reference, out, start + i)?;
            out.push(b);
        }
        Ok(())
    }
}

/// Byte at `idx` in the logical window (reference ++ output).
fn window_byte(reference: &[u8], out: &[u8], idx: usize) -> Result<u8, Error> {
    if idx < reference.len() {
        Ok(reference[idx])
    } else {
        out.get(idx - reference.len())
            .copied()
            .ok_or(Error::InvalidData("lzxd: match offset out of window"))
    }
}

/// E8 call translation reversal over one decompressed chunk
/// ([MS-PATCH] 2.2.2).
fn e8_reverse(chunk: &mut [u8], chunk_offset: i64, e8_file_size: i64) {
    let n = chunk.len();
    if n <= 10 {
        return;
    }
    let mut i = 0usize;
    while i + 5 <= n - 5 {
        if chunk[i] == 0xe8 {
            let cur = chunk_offset + i as i64;
            let value =
                i32::from_le_bytes([chunk[i + 1], chunk[i + 2], chunk[i + 3], chunk[i + 4]]) as i64;
            if value >= -cur && value < e8_file_size {
                let displacement = if value >= 0 {
                    value - cur
                } else {
                    value + e8_file_size
                };
                let d = displacement as u32;
                chunk[i + 1] = (d & 0xff) as u8;
                chunk[i + 2] = ((d >> 8) & 0xff) as u8;
                chunk[i + 3] = ((d >> 16) & 0xff) as u8;
                chunk[i + 4] = ((d >> 24) & 0xff) as u8;
            }
            i += 4;
        }
        i += 1;
    }
}

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
    decode_run(
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
    decode_run(input, window_size, reference, None, max_output)
}

fn decode_run(
    input: &[u8],
    window_size: usize,
    reference: &[u8],
    expected: Option<usize>,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    if expected == Some(0) || (expected.is_none() && input.is_empty()) {
        return Ok(Vec::new());
    }
    if !(1 << 17..=1 << 25).contains(&window_size) || !window_size.is_power_of_two() {
        return Err(Error::InvalidData("lzxd: window size out of range"));
    }
    let pos_slots = num_pos_slots(window_size);
    let mut d = Decoder {
        bits: BitReader::new(input),
        window_size,
        r: [1, 1, 1],
        main_lens: vec![0u8; NUM_LITERALS + 8 * pos_slots],
        length_lens: vec![0u8; LENGTH_TREE_ELEMENTS],
        block_type: 0,
        block_left: 0,
        block_size: 0,
        main_tree: None,
        length_tree: None,
        aligned_tree: None,
    };

    let mut out = Vec::with_capacity(expected.unwrap_or(0).min(max_output));

    // First bit of the stream: E8 translation flag, optionally followed by
    // two u16 fields forming the 32-bit translation size ([MS-PATCH] 2.2.2).
    let e8_enabled = d.bits.bits(1)? != 0;
    let e8_file_size: i64 = if e8_enabled {
        let hi = d.bits.bits(16)? as i64;
        let lo = d.bits.bits(16)? as i64;
        (hi << 16) | lo
    } else {
        0
    };

    let mut chunk_base = 0usize;
    'outer: loop {
        let chunk_target = match expected {
            Some(e) => (chunk_base + CHUNK_UNCOMPRESSED).min(e),
            None => chunk_base + CHUNK_UNCOMPRESSED,
        };
        loop {
            if out.len() >= chunk_target {
                break;
            }
            if d.block_left == 0 {
                if expected.is_none() && d.bits.at_end() {
                    // Final (partial) chunk: apply E8 reversal before
                    // returning, matching the per-chunk postprocessing.
                    if e8_enabled && chunk_base < 0x4000_0000 && out.len() - chunk_base > 10 {
                        e8_reverse(&mut out[chunk_base..], chunk_base as i64, e8_file_size);
                    }
                    break 'outer;
                }
                d.read_block_header()?;
            }
            match d.block_type {
                BLOCK_UNCOMPRESSED => {
                    let quota = (chunk_target - out.len()).min(d.block_left as usize);
                    for _ in 0..quota {
                        out.push(d.bits.raw_byte()?);
                    }
                    d.block_left -= quota as u64;
                    if d.block_left == 0 && d.block_size % 2 == 1 {
                        // Odd uncompressed size: one pad byte realigns the
                        // following bitstream.
                        let _ = d.bits.raw_byte()?;
                    }
                }
                _ => {
                    let before = out.len();
                    d.decode_element(reference, &mut out)?;
                    let produced = (out.len() - before) as u64;
                    if produced > d.block_left {
                        return Err(Error::InvalidData("lzxd: block size exceeded"));
                    }
                    d.block_left -= produced;
                }
            }
            if out.len() > chunk_target {
                return Err(Error::InvalidData("lzxd: match spans chunk boundary"));
            }
            if out.len() > max_output {
                return Err(Error::InvalidData("lzxd: output limit exceeded"));
            }
        }
        if e8_enabled && chunk_base < 0x4000_0000 && out.len() - chunk_base > 10 {
            e8_reverse(&mut out[chunk_base..], chunk_base as i64, e8_file_size);
        }
        d.bits.finish_chunk();
        chunk_base = out.len();
        if expected.is_some_and(|e| out.len() >= e) {
            break;
        }
    }
    Ok(out)
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
        let n = (input.len() - pos).min(CHUNK_UNCOMPRESSED);
        // Compressed chunk bytes: 2 header words + 12 (R0..R2) + data + pad.
        let csize = 4 + 12 + n + (n & 1);
        out.extend_from_slice(&(csize as u16).to_le_bytes());
        let size = n as u32;
        let (w0, w1) = if pos == 0 {
            // First chunk: 1-bit E8 flag (0) + 3-bit type + 24-bit size +
            // 4 pad bits.
            (
                (BLOCK_UNCOMPRESSED << 12) | ((size >> 12) & 0xfff),
                (size & 0xfff) << 4,
            )
        } else {
            // Later chunks: 3-bit type + 24-bit size + 5 pad bits.
            (
                (BLOCK_UNCOMPRESSED << 13) | ((size >> 11) & 0x1fff),
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
}
