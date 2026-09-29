//! LZX decompression core shared by the Cabinet LZX variant
//! (MS-CAB tcompTYPE_LZX folder compression) and the LZX DELTA variant
//! ([MS-PATCH]) exposed as compress::lzxd.
//!
//! The two variants share the LZX bitstream (16-bit little-endian words
//! consumed MSB-first), the block framing (verbatim / aligned-offset /
//! uncompressed), pretree-encoded Huffman code lengths, position slots,
//! the R0-R2 repeated-match-offset queue and E8 call translation. They
//! differ in:
//!
//! - the input container: LZXD interleaves u16 chunk-size prefixes,
//!   while Cabinet LZX is one contiguous byte stream (CFDATA record
//!   boundaries are irrelevant to the bitstream);
//! - the window size range: DELTA uses 2^17..=2^25 ([MS-PATCH] 2.1.2),
//!   Cabinet uses 2^15..=2^21;
//! - the DELTA-only >257 match-length extension field
//!   ([MS-PATCH] 2.6.6), which classic LZX does not have;
//! - Cabinet LZX skips the odd-size pad byte of an uncompressed block
//!   lazily when the next block header is read (so a trailing pad byte
//!   is never consumed) and does not require zero pad bits, matching
//!   the reference implementation's observed behaviour;
//! - Cabinet LZX only applies E8 reversal once a block that can emit
//!   literal 0xE8 bytes has been seen ("intel_started" in libmspack).
//!
//! The base format follows the Microsoft "LZX Data Compression Format"
//! document plus the corrections documented by Stuart Caie in
//! libmspack/cabextract: position-slot counts follow the implementation
//! (1 MiB = 42 slots, 2 MiB = 50; the document's table lists 40/42),
//! uncompressed blocks carry a 24-bit length field, the bitstream
//! padding ahead of uncompressed-block byte data is 1-16 bits (a fully
//! aligned block header still consumes a whole pad word), the aligned
//! offset tree precedes the main and length trees, aligned blocks
//! Huffman-decode the position footer's low 3 bits (including when the
//! footer is exactly 3 bits wide), and E8 leaders are not translated
//! within the last 10 bytes of a frame.
//!
//! [MS-PATCH]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Uncompressed bytes per output frame ([MS-PATCH] 2.2.1). LZX realigns
/// the bitstream to a 16-bit boundary after every 32 KiB of output.
pub(crate) const CHUNK_UNCOMPRESSED: usize = 32768;
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

pub(crate) const BLOCK_VERBATIM: u32 = 1;
const BLOCK_ALIGNED: u32 = 2;
pub(crate) const BLOCK_UNCOMPRESSED: u32 = 3;

/// Byte-wise input source. LZX DELTA wraps the compressed data in u16
/// little-endian chunk-size prefixes; Cabinet LZX
/// consumes one contiguous byte stream (limit spans the whole slice).
struct Source<'a> {
    data: &'a [u8],
    /// Next byte index to consume.
    pos: usize,
    /// End index of the current chunk's compressed data (chunked
    /// streams only; contiguous streams set limit = data.len()).
    limit: usize,
    /// Whether a chunk segment is currently open. A bitstream word fetch
    /// may only hop to the next chunk between output chunks; raw byte
    /// reads (uncompressed block payload) may hop freely.
    open: bool,
    chunked: bool,
}

impl<'a> Source<'a> {
    /// Chunked container source for LZX DELTA streams.
    #[cfg(feature = "lzxd")]
    fn chunked(data: &'a [u8]) -> Self {
        Source {
            data,
            pos: 0,
            limit: 0,
            open: false,
            chunked: true,
        }
    }

    /// Contiguous stream source for Cabinet LZX folders.
    #[cfg(feature = "mscab")]
    fn flat(data: &'a [u8]) -> Self {
        Source {
            data,
            pos: 0,
            limit: data.len(),
            open: true,
            chunked: false,
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

    /// Next bitstream byte: for chunked sources, hops to the next chunk
    /// only when no chunk is open (i.e., immediately after
    ///  or at stream start).
    fn stream_byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.limit {
            if self.chunked {
                if self.open {
                    return Err(Error::InvalidData("lzxd: element straddles chunk"));
                }
                self.load_chunk()?;
            } else {
                return Err(Error::InvalidData("lzxd: truncated input"));
            }
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Next raw byte (uncompressed-block payload, R0..R2 fields): for
    /// chunked sources may hop chunk boundaries mid-block.
    fn raw_byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.limit {
            if self.chunked {
                self.load_chunk()?;
            } else {
                return Err(Error::InvalidData("lzxd: truncated input"));
            }
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Discard the unconsumed remainder of the current chunk segment
    /// (chunked sources only).
    fn finish_chunk(&mut self) {
        debug_assert!(self.chunked);
        self.pos = self.limit;
        self.open = false;
    }

    /// True when no more compressed input remains. Any buffered bits at
    /// this point are stream-tail padding.
    fn at_end(&self) -> bool {
        self.pos >= self.limit && self.pos >= self.data.len()
    }
}

/// MSB-first bitreader over little-endian 16-bit words ([MS-PATCH] 2.1.1).
/// For chunked sources, word fetches are bounded to the current chunk
/// segment so that buffered bits left over at a chunk boundary are pure
/// zero padding.
struct BitReader<'a> {
    src: Source<'a>,
    buf: u64,
    cnt: u32,
    /// Pending high byte of a bitstream word returned as raw bytes.
    pending: Option<u8>,
}

impl<'a> BitReader<'a> {
    fn new(src: Source<'a>) -> Self {
        BitReader {
            src,
            buf: 0,
            cnt: 0,
            pending: None,
        }
    }

    fn bits(&mut self, n: u32) -> Result<u32, Error> {
        debug_assert!(n <= 32);
        debug_assert!(self.pending.is_none());
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

    /// Re-align the bitstream at an output frame (32 KiB) boundary.
    ///
    /// Chunked (DELTA) sources discard all buffered padding bits and the
    /// unfetched tail of the chunk segment. Contiguous (Cabinet) sources
    /// discard only the partial-word padding bits; whole words already
    /// buffered belong to the next frame.
    fn finish_frame(&mut self) {
        debug_assert!(self.pending.is_none());
        if self.src.chunked {
            self.buf = 0;
            self.cnt = 0;
            self.src.finish_chunk();
        } else {
            let pad = self.cnt % 16;
            self.cnt -= pad;
            self.buf &= (1u64 << self.cnt) - 1;
        }
    }

    /// True when no more compressed input remains. Any buffered bits at
    /// this point are stream-tail padding.
    fn at_end(&self) -> bool {
        self.src.at_end()
    }

    /// Discard the padding that precedes an uncompressed block's raw
    /// byte stream ([MS-PATCH] 2.3.2.1 "variable, [1..16] bits").
    ///
    /// Both variants use 1-16 bits of padding: a block header that lands
    /// exactly on a 16-bit boundary is still followed by a whole pad
    /// word (the LZX document's description is one of the errors noted
    /// in libmspack).  is always  at a block boundary, so the
    /// padding is exactly the buffered remainder, plus one fetched word
    /// when empty.
    ///
    /// DELTA streams additionally verify the pad bits are zero.
    fn align_uncompressed(&mut self, delta: bool) -> Result<(), Error> {
        debug_assert!(self.cnt < 16);
        let pad = if self.cnt == 0 { 16 } else { self.cnt };
        let v = self.bits(pad)?;
        if delta && v != 0 {
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
pub(crate) struct Huffman {
    /// Number of symbols with each code length, index 1..=16.
    pub(crate) counts: [u16; MAX_CODE_LENGTH + 1],
    /// Symbols sorted by (code length, symbol index).
    pub(crate) symbols: Vec<u16>,
}

impl Huffman {
    pub(crate) fn build(lens: &[u8]) -> Result<Huffman, Error> {
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
///
/// The same formula covers the Cabinet range 2^15..=2^21 (30/32/34/36/38
/// slots for 32-512 KiB windows, 42 for 1 MiB, 50 for 2 MiB), matching
/// the implementation rather than the LZX document's slot table (one of
/// the errors noted in libmspack).
pub(crate) fn num_pos_slots(window_size: usize) -> usize {
    debug_assert!(window_size.is_power_of_two());
    if window_size <= (1 << 19) {
        window_size.trailing_zeros() as usize * 2
    } else {
        (window_size >> 17) + 34
    }
}

/// Position-slot base position and footer bit count ([MS-PATCH] 2.6.2).
pub(crate) fn slot_base_footer(slot: usize) -> (u32, u32) {
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
    /// LZX DELTA semantics () vs classic Cabinet LZX ().
    delta: bool,
    window_size: usize,
    r: [u32; 3],
    main_lens: Vec<u8>,
    length_lens: Vec<u8>,
    /// Current block type and uncompressed bytes left to produce.
    block_type: u32,
    block_left: u64,
    block_size: u64,
    /// Cabinet streams skip the pad byte of an odd-length uncompressed
    /// block lazily, when the next block header is read; a pad byte at
    /// the end of the stream is never consumed.
    pad_pending: bool,
    /// Whether a block able to emit literal 0xE8 bytes has been seen:
    /// any uncompressed block, or a compressed block whose main tree
    /// assigns a code to 0xE8. Gates E8 reversal for Cabinet streams
    /// ("intel_started" in libmspack); the DELTA path applies E8
    /// whenever the stream flag is set.
    intel_started: bool,
    main_tree: Option<Huffman>,
    length_tree: Option<Huffman>,
    aligned_tree: Option<Huffman>,
}

impl<'a> Decoder<'a> {
    /// Decode a pretree ([MS-PATCH] 2.5: 20 elements, 4 bits each) then use
    /// it to decode the delta path lengths of  in place.
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
        if !self.delta && self.pad_pending {
            // Cabinet LZX: the pad byte of an odd-length uncompressed
            // block is skipped when the *next* block header is read.
            self.pad_pending = false;
            let _ = self.bits.raw_byte()?;
        }
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
                self.bits.align_uncompressed(self.delta)?;
                self.r[0] = self.bits.raw_u32()?;
                self.r[1] = self.bits.raw_u32()?;
                self.r[2] = self.bits.raw_u32()?;
                // A raw byte stream can carry literal 0xE8 bytes, so E8
                // translation may start.
                self.intel_started = true;
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
                // If the literal 0xE8 can appear in this block, E8
                // translation may start.
                if self.main_lens[0xE8] != 0 {
                    self.intel_started = true;
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    /// Decode one verbatim/aligned element, appending to .
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
                // In aligned-offset blocks the position footer's low 3
                // bits are always Huffman-coded with the aligned tree,
                // including when the footer is exactly 3 bits wide (a
                // documented LZX spec error corrected by libmspack).
                let footer = if self.block_type == BLOCK_ALIGNED && footer_bits >= 3 {
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

        if self.delta && match_len == 257 {
            // Extra length field ([MS-PATCH] 2.6.6); classic LZX has no
            // such field and caps match lengths at 257.
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

/// Byte at idx in the logical window (reference ++ output).
fn window_byte(reference: &[u8], out: &[u8], idx: usize) -> Result<u8, Error> {
    if idx < reference.len() {
        Ok(reference[idx])
    } else {
        out.get(idx - reference.len())
            .copied()
            .ok_or(Error::InvalidData("lzxd: match offset out of window"))
    }
}

/// E8 call translation reversal over one decompressed frame
/// ([MS-PATCH] 2.2.2). E8 leaders are never translated in the last 10
/// bytes of the frame.
pub(crate) fn e8_reverse(chunk: &mut [u8], chunk_offset: i64, e8_file_size: i64) {
    let n = chunk.len();
    let mut i = 0usize;
    while i + 10 < n {
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

/// Shared decode loop for both LZX variants.
///
/// - src: chunked (LZX DELTA) or contiguous (Cabinet) input source.
/// - window_size: sliding window; 2^17..=2^25 for DELTA
///   ([MS-PATCH] 2.1.2), 2^15..=2^21 for Cabinet.
/// - reference: DELTA reference bytes, empty for Cabinet streams.
/// - expected: uncompressed size; None (DELTA only) decodes until
///   the compressed input is exhausted.
/// - delta: selects the variant rules documented at the module top.
fn decode_run(
    src: Source<'_>,
    window_size: usize,
    reference: &[u8],
    expected: Option<usize>,
    max_output: usize,
    delta: bool,
) -> Result<Vec<u8>, Error> {
    let window_ok = if delta {
        (1 << 17..=1 << 25).contains(&window_size)
    } else {
        (1 << 15..=1 << 21).contains(&window_size)
    };
    if !window_ok || !window_size.is_power_of_two() {
        return Err(Error::InvalidData("lzxd: window size out of range"));
    }
    if expected == Some(0) || (expected.is_none() && src.at_end()) {
        return Ok(Vec::new());
    }
    let pos_slots = num_pos_slots(window_size);
    let mut d = Decoder {
        bits: BitReader::new(src),
        delta,
        window_size,
        r: [1, 1, 1],
        main_lens: vec![0u8; NUM_LITERALS + 8 * pos_slots],
        length_lens: vec![0u8; LENGTH_TREE_ELEMENTS],
        block_type: 0,
        block_left: 0,
        block_size: 0,
        pad_pending: false,
        intel_started: false,
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

    // DELTA reverses E8 whenever the stream flag is set; Cabinet LZX
    // additionally requires intel_started (a block able to emit 0xE8 has
    // been seen) and a nonzero translation size (libmspack semantics).
    let e8_active = |d: &Decoder| {
        if delta {
            e8_enabled
        } else {
            e8_enabled && e8_file_size != 0 && d.intel_started
        }
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
                    // Final (partial) frame: apply E8 reversal before
                    // returning, matching the per-frame postprocessing.
                    if e8_active(&d) && chunk_base < 0x4000_0000 && out.len() - chunk_base > 10 {
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
                        if delta {
                            // Odd uncompressed size: one pad byte
                            // realigns the following bitstream.
                            let _ = d.bits.raw_byte()?;
                        } else {
                            // Cabinet streams skip the pad byte when the
                            // next block header is read.
                            d.pad_pending = true;
                        }
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
        if e8_active(&d) && chunk_base < 0x4000_0000 && out.len() - chunk_base > 10 {
            e8_reverse(&mut out[chunk_base..], chunk_base as i64, e8_file_size);
        }
        d.bits.finish_frame();
        chunk_base = out.len();
        if expected.is_some_and(|e| out.len() >= e) {
            break;
        }
    }
    Ok(out)
}

/// Decode an LZX DELTA stream ([MS-PATCH]).
///
/// expected: Some(n) decodes exactly n uncompressed bytes;
/// None decodes until the chunked input is exhausted (blocks are
/// self-terminating via their 24-bit size).
#[cfg(feature = "lzxd")]
pub(crate) fn decode_delta(
    input: &[u8],
    window_size: usize,
    reference: &[u8],
    expected: Option<usize>,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    decode_run(
        Source::chunked(input),
        window_size,
        reference,
        expected,
        max_output,
        true,
    )
}

/// Decode a Cabinet LZX (tcompTYPE_LZX) folder stream.
///
/// input is the concatenation of the folder's CFDATA payloads (the
/// LZX bitstream is contiguous across CFDATA records); window_size
/// derives from the CFFOLDER typeCompress high bits
/// (2^15..=2^21); expected is the folder's total uncompressed
/// size (the sum of cbUncomp over the logical folder's blocks).
#[cfg(feature = "mscab")]
pub(crate) fn decode_cabinet(
    input: &[u8],
    window_size: usize,
    expected: usize,
) -> Result<Vec<u8>, Error> {
    decode_run(
        Source::flat(input),
        window_size,
        &[],
        Some(expected),
        usize::MAX,
        false,
    )
}

// -------------------------------------------------------------------
// Cabinet-LZX test support: a minimal classic-LZX encoder producing
// verbatim / aligned / uncompressed blocks over a contiguous stream
// (no chunk prefixes). Generated vectors were validated against
// libmspack's lzxd decompressor.
// -------------------------------------------------------------------
#[cfg(all(test, feature = "mscab"))]
pub(crate) mod cabtest {
    #![allow(dead_code)]

    use alloc::vec;
    use alloc::vec::Vec;

    pub const NUM_LIT: usize = 256;

    /// MSB-first bit writer emitting little-endian u16 words.
    pub struct Bits {
        pub out: Vec<u8>,
        acc: u32,
        n: u32,
    }
    impl Bits {
        pub fn new() -> Self {
            Bits {
                out: vec![],
                acc: 0,
                n: 0,
            }
        }
        pub fn bits(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.acc = (self.acc << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.out.push((self.acc & 0xff) as u8);
                    self.out.push(((self.acc >> 8) & 0xff) as u8);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }
        /// Pad the bitstream to a 16-bit boundary; when already aligned,
        /// emit a whole pad word (Cabinet uncompressed blocks use 1-16
        /// padding bits, never 0).
        pub fn pad16(&mut self) {
            if self.n == 0 {
                self.bits(0, 16);
            } else {
                while self.n != 0 {
                    self.bits(0, 1);
                }
            }
        }
        /// Pad to a 16-bit boundary with 0-15 bits (frame realignment).
        pub fn align16(&mut self) {
            while self.n != 0 {
                self.bits(0, 1);
            }
        }
        pub fn raw(&mut self, bs: &[u8]) {
            debug_assert_eq!(self.n % 8, 0);
            if self.n == 8 {
                self.out.push((self.acc & 0xff) as u8);
                self.acc = 0;
                self.n = 0;
            }
            debug_assert_eq!(self.n, 0);
            self.out.extend_from_slice(bs);
        }
    }

    /// Canonical codes for a length set (same order as the decoder's
    /// symbol sort: by code length, then symbol index).
    pub fn canon(lens: &[u8]) -> Vec<u32> {
        let mut codes = vec![0u32; lens.len()];
        let mut code = 0u32;
        for l in 1u8..=16 {
            for (s, &sl) in lens.iter().enumerate() {
                if sl == l {
                    codes[s] = code;
                    code += 1;
                }
            }
            code <<= 1;
        }
        codes
    }

    pub fn slot_bf(slot: usize) -> (u32, u32) {
        if slot < 4 {
            (slot as u32, 0)
        } else if slot < 36 {
            let f = (slot >> 1) - 1;
            (((2 + (slot & 1)) << f) as u32, f as u32)
        } else {
            (((slot - 34) << 17) as u32, 17)
        }
    }
    pub fn slot_for(formatted: u32) -> usize {
        let mut s = 0usize;
        while slot_bf(s + 1).0 <= formatted {
            s += 1;
        }
        s
    }
    pub fn nslots(window: usize) -> usize {
        if window <= 1 << 19 {
            window.trailing_zeros() as usize * 2
        } else {
            (window >> 17) + 34
        }
    }

    #[derive(Clone, Copy)]
    pub enum Elem {
        Lit(u8),
        Match { len: usize, offset: u32 },
        RMatch { len: usize, r: usize },
    }
    impl Elem {
        pub fn produced(&self) -> usize {
            match *self {
                Elem::Lit(_) => 1,
                Elem::Match { len, .. } | Elem::RMatch { len, .. } => len,
            }
        }
    }

    #[derive(Clone)]
    pub struct Trees {
        pub main: Vec<u8>,
        pub len: Vec<u8>,
        pub aligned: [u8; 8],
    }

    /// Complete-tree code lengths (Kraft sum = 1) for a used-symbol set.
    pub fn complete_lens(total: usize, used: &[usize]) -> Vec<u8> {
        let mut lens = vec![0u8; total];
        let mut used: Vec<usize> = used.to_vec();
        used.sort();
        used.dedup();
        if used.is_empty() {
            return lens;
        }
        if used.len() == 1 {
            lens[used[0]] = 1;
            let other = (0..total).find(|&i| i != used[0]).unwrap();
            lens[other] = 1;
            return lens;
        }
        let n = used.len();
        let l = (usize::BITS - (n - 1).leading_zeros()) as usize;
        let b = (1usize << l) - n;
        let a = n - b;
        for (i, &sym) in used.iter().enumerate() {
            lens[sym] = if i < a { l as u8 } else { (l - 1) as u8 };
        }
        lens
    }

    pub fn trees_for(
        lits: &[usize],
        matches: &[usize],
        lens: &[usize],
        aligned_used: &[usize],
        nsl: usize,
    ) -> Trees {
        let mut mainset: Vec<usize> = lits.to_vec();
        mainset.extend(matches.iter().map(|i| NUM_LIT + i));
        let main = complete_lens(NUM_LIT + 8 * nsl, &mainset);
        let ln = complete_lens(249, lens);
        let alv = complete_lens(8, aligned_used);
        let mut al = [0u8; 8];
        al.copy_from_slice(&alv);
        Trees {
            main,
            len: ln,
            aligned: al,
        }
    }

    /// Cabinet LZX stream encoder: contiguous bitstream, realigned to a
    /// 16-bit boundary after every 32 KiB of produced output.
    pub struct Enc {
        pub out: Vec<u8>,
        seg: Bits,
        started: bool,
        e8: Option<u32>,
        pub nslots: usize,
        prev: Option<Trees>,
        block_aligned: bool,
        /// Uncompressed bytes produced so far (frame tracking).
        produced: usize,
    }

    impl Enc {
        pub fn new(window: usize, e8: Option<u32>) -> Self {
            Enc {
                out: vec![],
                seg: Bits::new(),
                started: false,
                e8,
                nslots: nslots(window),
                prev: None,
                block_aligned: false,
                produced: 0,
            }
        }

        fn emit_tree(&mut self, new: &[u8], prev: &[u8]) {
            // Complete pretree: 12 x len 4 + 8 x len 5 (Kraft = 1).
            static PT: [u8; 20] = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5];
            let pc = canon(&PT);
            for &l in PT.iter() {
                self.seg.bits(l as u32, 4);
            }
            for (&p, &n) in prev.iter().zip(new.iter()) {
                let code = (p as i32 - n as i32).rem_euclid(17) as u32;
                self.seg.bits(pc[code as usize], PT[code as usize] as u32);
            }
        }

        fn header(&mut self) {
            if !self.started {
                match self.e8 {
                    Some(sz) => {
                        self.seg.bits(1, 1);
                        self.seg.bits(sz >> 16, 16);
                        self.seg.bits(sz & 0xffff, 16);
                    }
                    None => self.seg.bits(0, 1),
                }
                self.started = true;
            }
        }

        /// Realign the bitstream when produced output lands on a 32 KiB
        /// frame boundary.
        fn frame_realign(&mut self) {
            if self.produced.is_multiple_of(32768) {
                self.seg.align16();
            }
        }

        pub fn uncompressed(&mut self, data: &[u8], r: [u32; 3]) {
            self.header();
            self.seg.bits(3, 3);
            self.seg.bits(data.len() as u32, 24);
            self.seg.pad16();
            let mut rb = Vec::new();
            for v in r {
                rb.extend_from_slice(&v.to_le_bytes());
            }
            rb.extend_from_slice(data);
            self.seg.raw(&rb);
            if data.len() % 2 == 1 {
                // Cabinet streams carry the pad byte here; the decoder
                // skips it when the next block header is read.
                self.seg.raw(&[0]);
            }
            self.produced += data.len();
            self.frame_realign();
        }

        /// Emit a verbatim (aligned == false) or aligned-offset block.
        ///  = uncompressed bytes produced by .
        pub fn compressed(&mut self, aligned: bool, size: u32, trees: &Trees, elems: &[Elem]) {
            self.header();
            self.block_aligned = aligned;
            self.seg.bits(if aligned { 2 } else { 1 }, 3);
            self.seg.bits(size, 24);
            if aligned {
                for i in 0..8 {
                    self.seg.bits(trees.aligned[i] as u32, 3);
                }
            }
            let zeros_main = vec![0u8; trees.main.len()];
            let zeros_len = vec![0u8; 249];
            let (pm1, pm2, pl) = match &self.prev {
                Some(p) => (
                    p.main[..NUM_LIT].to_vec(),
                    p.main[NUM_LIT..].to_vec(),
                    p.len.clone(),
                ),
                None => (
                    zeros_main[..NUM_LIT].to_vec(),
                    zeros_main[NUM_LIT..].to_vec(),
                    zeros_len,
                ),
            };
            self.emit_tree(&trees.main[..NUM_LIT], &pm1);
            self.emit_tree(&trees.main[NUM_LIT..], &pm2);
            self.emit_tree(&trees.len, &pl);
            self.prev = Some(trees.clone());
            self.emit_elems(trees, elems);
            self.produced += size as usize;
            self.frame_realign();
        }

        fn emit_elems(&mut self, trees: &Trees, elems: &[Elem]) {
            let mc = canon(&trees.main);
            let lc = canon(&trees.len);
            let ac = canon(&trees.aligned);
            for e in elems {
                match *e {
                    Elem::Lit(b) => {
                        self.seg.bits(mc[b as usize], trees.main[b as usize] as u32);
                    }
                    Elem::Match { len, offset } => {
                        let formatted = offset + 2;
                        let slot = slot_for(formatted);
                        self.emit_match(len, slot, formatted, trees, &mc, &lc, &ac);
                    }
                    Elem::RMatch { len, r } => {
                        self.emit_match(len, r, r as u32, trees, &mc, &lc, &ac);
                    }
                }
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn emit_match(
            &mut self,
            len: usize,
            slot: usize,
            formatted: u32,
            t: &Trees,
            mc: &[u32],
            lc: &[u32],
            ac: &[u32],
        ) {
            // Classic LZX has no >257 match-length extension.
            assert!(len <= 257);
            let (header, len_elem) = if len <= 8 {
                (len - 2, None)
            } else {
                (7, Some(len - 9))
            };
            let elem = NUM_LIT + slot * 8 + header;
            self.seg.bits(mc[elem], t.main[elem] as u32);
            if let Some(le) = len_elem {
                self.seg.bits(lc[le], t.len[le] as u32);
            }
            let (base, fbits) = slot_bf(slot);
            let footer = formatted - base;
            if self.block_aligned && fbits >= 3 {
                self.seg.bits(footer >> 3, fbits - 3);
                self.seg.bits(
                    ac[(footer & 7) as usize],
                    t.aligned[(footer & 7) as usize] as u32,
                );
            } else if fbits > 0 {
                self.seg.bits(footer, fbits);
            }
        }

        /// Flush remaining bits; returns the contiguous CAB LZX stream.
        pub fn finish(mut self) -> Vec<u8> {
            self.seg.align16();
            self.out.append(&mut self.seg.out);
            self.out
        }
    }

    /// Simulate element output (no reference data for Cabinet LZX).
    pub fn simulate(elems: &[Elem]) -> Vec<u8> {
        let mut win: Vec<u8> = Vec::new();
        let mut r = [1u32, 1, 1];
        for el in elems {
            match *el {
                Elem::Lit(b) => win.push(b),
                Elem::Match { len, offset } => {
                    let st = win.len() - offset as usize;
                    for i in 0..len {
                        let b = win[st + i];
                        win.push(b);
                    }
                    r = [offset, r[0], r[1]];
                }
                Elem::RMatch { len, r: rr } => {
                    let off = r[rr] as usize;
                    let st = win.len() - off;
                    for i in 0..len {
                        let b = win[st + i];
                        win.push(b);
                    }
                    match rr {
                        1 => r.swap(0, 1),
                        2 => r.swap(0, 2),
                        _ => {}
                    }
                }
            }
        }
        win
    }

    pub fn match_elem_index(len: usize, offset: u32) -> usize {
        let slot = slot_for(offset + 2);
        let hdr = if len <= 8 { len - 2 } else { 7 };
        slot * 8 + hdr
    }
}

#[cfg(all(test, feature = "mscab"))]
mod tests {
    use super::cabtest::{Elem, Enc, simulate, trees_for};
    use super::*;

    const W15: usize = 1 << 15;
    const W18: usize = 1 << 18;

    /// Straightforward verbatim block of literal bytes.
    #[test]
    fn cab_verbatim_block() {
        let data = b"verbatim cabinet lzx block";
        let mut lits: Vec<usize> = data.iter().map(|&b| b as usize).collect();
        lits.sort();
        lits.dedup();
        let trees = trees_for(&lits, &[], &[], &[], 30);
        let mut e = Enc::new(W15, None);
        let elems: Vec<Elem> = data.iter().map(|&b| Elem::Lit(b)).collect();
        e.compressed(false, data.len() as u32, &trees, &elems);
        let stream = e.finish();
        let out = decode_cabinet(&stream, W15, data.len()).unwrap();
        assert_eq!(out, data);
    }

    /// Aligned-offset block: literals plus a match whose position footer
    /// exercises the aligned Huffman tree.
    #[test]
    fn cab_aligned_block() {
        // 40 literal bytes, then a match with formatted offset 39
        // (position slot 8: base 32, 3 footer bits -> the whole footer is
        // aligned-tree coded), then one more literal.
        let mut elems: Vec<Elem> = (0u8..40).map(Elem::Lit).collect();
        elems.push(Elem::Match {
            len: 12,
            offset: 37,
        });
        elems.push(Elem::Lit(b'z'));
        let want = simulate(&elems);
        let mut lits: Vec<usize> = (0usize..40).collect();
        lits.push(b'z' as usize);
        // Match element index: formatted offset 39 -> position slot 10
        // (base 32, 4 footer bits -> 1 verbatim + 3 aligned-tree bits),
        // length 12 -> length header 7 + length-tree element 3.
        let mel = 10 * 8 + 7;
        let trees = trees_for(&lits, &[mel], &[3], &[7], 30);
        let mut e = Enc::new(W15, None);
        e.compressed(true, want.len() as u32, &trees, &elems);
        let stream = e.finish();
        let out = decode_cabinet(&stream, W15, want.len()).unwrap();
        assert_eq!(out, want);
    }

    /// Uncompressed block, including the odd-size deferred pad byte.
    #[test]
    fn cab_uncompressed_block_odd_pad() {
        let mut e = Enc::new(W15, None);
        e.uncompressed(b"odd", [1, 1, 1]); // 3 bytes: pad byte follows
        // A second block must still decode: pad byte skipped lazily.
        let elems = vec![Elem::Lit(b'X'), Elem::Lit(b'Y')];
        let trees = trees_for(&[b'X' as usize, b'Y' as usize], &[], &[], &[], 30);
        e.compressed(false, 2, &trees, &elems);
        let stream = e.finish();
        let out = decode_cabinet(&stream, W15, 5).unwrap();
        assert_eq!(out, b"oddXY");
    }

    /// Repeated-match offsets (R0/R1/R2 queue) in a verbatim block.
    #[test]
    fn cab_verbatim_matches_and_repeats() {
        let elems = vec![
            Elem::Lit(b'a'),
            Elem::Lit(b'b'),
            Elem::Lit(b'c'),
            Elem::Lit(b'd'),
            Elem::Lit(b'e'),
            Elem::Lit(b'f'),
            Elem::Lit(b'g'),
            Elem::Lit(b'h'),
            Elem::Match { len: 6, offset: 8 },
            Elem::Lit(b'!'),
            Elem::RMatch { len: 4, r: 0 },
            Elem::Lit(b'?'),
            Elem::RMatch { len: 3, r: 1 },
        ];
        let want = simulate(&elems);
        let mut lits: Vec<usize> = want.iter().map(|&b| b as usize).collect();
        lits.sort();
        lits.dedup();
        // Match element indices: position slot * 8 + length header.
        // Match{6, off 8}: formatted 10 -> slot 6 (base 8, 2 footer bits)
        // -> 6*8 + (6-2) = 52. RMatches use repeated-offset slots
        // r*8 + (len-2): r0/len4 -> 2, r1/len3 -> 9. All lengths are
        // <= 8, so no length-tree elements.
        let trees = trees_for(&lits, &[52, 2, 9], &[], &[], 30);
        let mut e = Enc::new(W15, None);
        e.compressed(false, want.len() as u32, &trees, &elems);
        let stream = e.finish();
        let out = decode_cabinet(&stream, W15, want.len()).unwrap();
        assert_eq!(out, want);
    }

    /// Multi-frame stream: output crossing the 32 KiB frame boundary
    /// forces bitstream realignment inside the contiguous stream.
    #[test]
    fn cab_multi_frame_realign() {
        let mut e = Enc::new(W15, None);
        // First block produces exactly one 32 KiB frame, then a second
        // block continues the same contiguous stream.
        let d1 = vec![0x41u8; 32768];
        e.uncompressed(&d1, [1, 1, 1]);
        let elems = vec![Elem::Lit(b'A'), Elem::Match { len: 9, offset: 1 }];
        let part2 = simulate(&elems);
        let m = cabtest::match_elem_index(9, 1);
        let trees = trees_for(&[b'A' as usize], &[m], &[0], &[], 30);
        e.compressed(false, part2.len() as u32, &trees, &elems);
        let stream = e.finish();
        let mut want = d1.clone();
        want.extend_from_slice(&part2);
        let out = decode_cabinet(&stream, W15, want.len()).unwrap();
        assert_eq!(out, want);
    }

    /// E8 call translation reversal on a Cabinet stream (requires the
    /// main tree to carry 0xE8 before reversal engages).
    #[test]
    fn cab_e8_translation() {
        // Build a block that emits an E8 leader plus 4 bytes so that
        // intel_started engages; the encoder side wrote pre-translated
        // values, so simulate() gives the decoded expectation.
        let mut data = vec![0u8; 40];
        data[0] = 0xe8;
        // Stored absolute file offset 5 at position 0: rel32 = 5 - 0.
        data[1..5].copy_from_slice(&5i32.to_le_bytes());
        // Stored absolute offset 10 at position 20: rel32 = 10 - 20.
        data[20] = 0xe8;
        data[21..25].copy_from_slice(&10i32.to_le_bytes());
        // An E8 leader in the last 10 bytes of the frame is NOT
        // translated.
        data[35] = 0xe8;
        data[36..40].copy_from_slice(&3i32.to_le_bytes());
        let mut e = Enc::new(W15, Some(data.len() as u32));
        e.uncompressed(&data, [1, 1, 1]);
        let stream = e.finish();
        let out = decode_cabinet(&stream, W15, data.len()).unwrap();
        let mut want = data.clone();
        want[21..25].copy_from_slice(&(-10i32).to_le_bytes());
        assert_eq!(out, want);
    }

    /// Window sizes outside 2^15..=2^21 are rejected for Cabinet LZX.
    #[test]
    fn cab_rejects_bad_window() {
        let mut e = Enc::new(W15, None);
        e.uncompressed(b"ab", [1, 1, 1]);
        let stream = e.finish();
        assert!(decode_cabinet(&stream, 1 << 14, 2).is_err());
        assert!(decode_cabinet(&stream, 1 << 22, 2).is_err());
        assert!(decode_cabinet(&stream, W15, 2).is_ok());
        assert!(decode_cabinet(&stream, 1 << 21, 2).is_ok());
    }

    /// Truncated streams and size mismatches error out.
    #[test]
    fn cab_rejects_truncated() {
        let mut e = Enc::new(W15, None);
        e.uncompressed(b"hello", [1, 1, 1]);
        let stream = e.finish();
        for n in [0usize, 1, 5, stream.len() - 2] {
            assert!(decode_cabinet(&stream[..n], W15, 5).is_err(), "n={n}");
        }
        // The trailing pad byte of an odd uncompressed block is only
        // consumed when a next block header is read, so dropping it is
        // still a valid stream.
        assert_eq!(
            decode_cabinet(&stream[..stream.len() - 1], W15, 5).unwrap(),
            b"hello"
        );
        // Mismatched expected size.
        assert!(decode_cabinet(&stream, W15, 6).is_err());
    }

    /// Real Microsoft-encoder Cabinet LZX stream (cabextract test data,
    /// folder 1 of mixed.cab, window 2^18, E8 enabled).
    #[test]
    fn cab_fixture_mixed_lzx() {
        let stream = include_bytes!("../../tests/fixtures/mscab/mixed_lzx.lzx");
        let want = include_bytes!("../../tests/fixtures/mscab/mixed_lzx.txt");
        let out = decode_cabinet(stream, W18, want.len()).unwrap();
        assert_eq!(&out[..], &want[..]);
    }
}
