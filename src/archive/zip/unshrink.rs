//! ZIP Method 1 (Shrinking / UnShrinking) codec.
//!
//! Implements the LZW variant described in APPNOTE §5.1.
//! Code width starts at 9 bits and can grow up to 13 bits.
//! Code 256 is a special control code: followed by 1 it increases code width,
//! followed by 2 it performs a partial clear (frees leaf dictionary entries).
//! Freed codes are re-used in increasing order via a code queue, matching the
//! reference implementation (hwzip, public domain).

use alloc::vec::Vec;

use crate::error::Error;

/// Maximum code width for UnShrink (APPNOTE §5.1).
const MAX_BITS: u32 = 13;
/// Initial code width.
const INIT_BITS: u32 = 9;
/// Special control code.
const CONTROL_CODE: u16 = 256;
/// Control sub-code: increase the code width by one bit.
const INC_CODE_SIZE: u16 = 1;
/// Control sub-code: partial clear of the dictionary.
const PARTIAL_CLEAR: u16 = 2;
/// First dictionary code (codes 0-255 are literals, 256 is control).
const FIRST_CODE: u16 = 257;
/// Maximum code value.
const MAX_CODE: u16 = (1 << MAX_BITS) - 1;
/// Number of dictionary slots (2^13 = 8192).
const DICT_SIZE: usize = 1 << MAX_BITS;
/// Marker for an invalid dictionary entry / empty code queue.
const INVALID_CODE: u16 = u16::MAX;

// ======================================================================
// Decoder
// ======================================================================

/// Dictionary entry for the decoder.
///
/// The decoder tracks the position of each code's expansion inside `output`,
/// which makes partial-clearing and the KwKwK cases exact without walking
/// prefix chains.
#[derive(Clone, Copy)]
struct DecEntry {
    /// Parent code, or [`INVALID_CODE`] when the entry is free.
    prefix: u16,
    /// Extension byte of this code's string.
    ext: u8,
    /// Expansion length, or [`UNKNOWN_LEN`] while indeterminate.
    len: u16,
    /// Position of this code's expansion in the output buffer.
    pos: usize,
}

/// Marker for an entry whose expansion length is not yet known.
const UNKNOWN_LEN: u16 = u16::MAX;

/// Queue of free dictionary codes in allocation order.
struct CodeQueue {
    codes: Vec<u16>,
    head: usize,
}

impl CodeQueue {
    /// All dictionary codes are initially free, in increasing order.
    fn new() -> Self {
        let mut codes = Vec::with_capacity(DICT_SIZE - FIRST_CODE as usize + 1);
        for c in FIRST_CODE..=MAX_CODE {
            codes.push(c);
        }
        codes.push(INVALID_CODE); // end-of-queue marker
        Self { codes, head: 0 }
    }

    /// The next free code without removing it.
    fn peek(&self) -> u16 {
        self.codes[self.head]
    }

    /// Remove and return the next free code (INVALID_CODE when empty).
    fn pop(&mut self) -> u16 {
        let c = self.peek();
        if c != INVALID_CODE {
            self.head += 1;
        }
        c
    }
}

/// Decompress data compressed with ZIP Method 1 (Shrinking).
///
/// The input must be the raw compressed payload (no ZIP local file header).
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the bitstream is malformed or a code
/// references an invalid dictionary entry.
pub(super) fn unshrink(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut table = vec![
        DecEntry {
            prefix: INVALID_CODE,
            ext: 0,
            len: 1,
            pos: 0,
        };
        DICT_SIZE
    ];
    // Literals are always valid with length 1.
    for i in 0u16..=255 {
        table[i as usize].prefix = i;
        table[i as usize].ext = i as u8;
    }
    table[CONTROL_CODE as usize].prefix = CONTROL_CODE;

    let mut queue = CodeQueue::new();
    let mut bits = BitReader::new(input);
    let mut code_size = INIT_BITS;
    let mut output = Vec::new();

    // The first code must be a literal byte.
    let prev_code = match read_code(&mut bits, &mut code_size, &mut table, &mut queue)? {
        Some(c) => c,
        None => return Ok(output),
    };
    if prev_code == INVALID_CODE || prev_code > 255 {
        return Err(Error::InvalidData("unshrink: first code must be a literal"));
    }
    let mut first_byte = prev_code as u8;
    output.push(first_byte);
    table[prev_code as usize].pos = 0;
    let mut prev_code = prev_code;

    while let Some(code) = read_code(&mut bits, &mut code_size, &mut table, &mut queue)? {
        if code == INVALID_CODE {
            return Err(Error::InvalidData("unshrink: invalid code"));
        }

        // KwKwK case: the code being read is the slot that is about to be
        // assigned for prev_code extended with first_byte.
        if code == queue.peek() {
            if table[prev_code as usize].prefix == INVALID_CODE {
                return Err(Error::InvalidData("unshrink: KwKwK with invalid prefix"));
            }
            let prev = table[prev_code as usize];
            table[code as usize] = DecEntry {
                prefix: prev_code,
                ext: first_byte,
                len: prev.len + 1,
                pos: prev.pos,
            };
        }

        let out_start = output.len();
        output_code(
            code,
            &mut output,
            &mut table,
            &queue,
            prev_code,
            &mut first_byte,
        )?;

        // Add a new dictionary entry: prev_code + first_byte.
        let new_code = queue.pop();
        if new_code != INVALID_CODE {
            let prev = table[prev_code as usize];
            let mut len = prev.len + 1;
            if prev.prefix == INVALID_CODE {
                // prev_code was invalidated by a partial clear; the new
                // entry's expansion is indeterminate until its prefix is
                // assigned again.
                len = UNKNOWN_LEN;
            }
            table[new_code as usize] = DecEntry {
                prefix: prev_code,
                ext: first_byte,
                len,
                pos: prev.pos,
            };
        }

        table[code as usize].pos = out_start;
        prev_code = code;
    }

    Ok(output)
}

/// Read one code, transparently handling control codes. Returns `Ok(None)` at
/// the end of the stream and `Ok(Some(INVALID_CODE))` for invalid control
/// codes.
fn read_code(
    bits: &mut BitReader<'_>,
    code_size: &mut u32,
    table: &mut [DecEntry],
    queue: &mut CodeQueue,
) -> Result<Option<u16>, Error> {
    loop {
        let code = match bits.try_read_bits(*code_size) {
            Some(c) => c as u16,
            None => return Ok(None),
        };
        if code != CONTROL_CODE {
            return Ok(Some(code));
        }
        let sub = match bits.try_read_bits(*code_size) {
            Some(c) => c as u16,
            None => return Ok(None),
        };
        match sub {
            INC_CODE_SIZE if *code_size < MAX_BITS => *code_size += 1,
            PARTIAL_CLEAR => dec_partial_clear(table, queue),
            _ => return Ok(Some(INVALID_CODE)),
        }
    }
}

/// Partial clear (decoder side): invalidate non-leaf-free entries and refill
/// the queue with the freed codes in increasing order.
fn dec_partial_clear(table: &mut [DecEntry], queue: &mut CodeQueue) {
    let mut is_prefix = [false; DICT_SIZE];
    for e in table.iter().skip(FIRST_CODE as usize) {
        if e.prefix != INVALID_CODE {
            is_prefix[e.prefix as usize] = true;
        }
    }
    let mut codes = Vec::with_capacity(DICT_SIZE - FIRST_CODE as usize + 1);
    for i in FIRST_CODE..=MAX_CODE {
        if !is_prefix[i as usize] {
            table[i as usize].prefix = INVALID_CODE;
            codes.push(i);
        }
    }
    codes.push(INVALID_CODE);
    queue.codes = codes;
    queue.head = 0;
}

/// Emit the expansion of `code` into `output` and update `first_byte`.
fn output_code(
    code: u16,
    output: &mut Vec<u8>,
    table: &mut [DecEntry],
    queue: &CodeQueue,
    prev_code: u16,
    first_byte: &mut u8,
) -> Result<(), Error> {
    let dst_pos = output.len();
    if code < 256 {
        output.push(code as u8);
        *first_byte = code as u8;
        return Ok(());
    }
    let idx = code as usize;
    if table[idx].prefix == INVALID_CODE || table[idx].prefix == code {
        return Err(Error::InvalidData("unshrink: invalid dictionary entry"));
    }

    if table[idx].len != UNKNOWN_LEN {
        // Copy the previously emitted expansion (1-byte overlap allowed).
        let len = table[idx].len as usize;
        let src = table[idx].pos;
        for i in 0..len {
            let b = output[src + i];
            output.push(b);
        }
        *first_byte = output[dst_pos];
        return Ok(());
    }

    // Length unknown: the entry was created while its prefix was invalid.
    let prefix = table[idx].prefix;
    if prefix == queue.peek() {
        // The prefix is the slot about to be assigned (nested KwKwK).
        // It expands to prev_code's string extended with the first byte of
        // the previous output, which is still in `first_byte`.
        if table[prev_code as usize].prefix == INVALID_CODE {
            return Err(Error::InvalidData("unshrink: prefix invalidated"));
        }
        let prev = table[prev_code as usize];
        table[prefix as usize] = DecEntry {
            prefix: prev_code,
            ext: *first_byte,
            len: prev.len + 1,
            pos: prev.pos,
        };
        // The copy below reads one byte past prev's expansion, which lands
        // on dst_pos; by then it holds the first byte of prev's expansion,
        // i.e. *first_byte — exactly the extension byte of this entry.
    }
    if table[prefix as usize].prefix == INVALID_CODE || table[prefix as usize].len == UNKNOWN_LEN {
        return Err(Error::InvalidData("unshrink: indeterminate prefix"));
    }
    let plen = table[prefix as usize].len as usize;
    let src = table[prefix as usize].pos;
    for i in 0..plen {
        let b = output[src + i];
        output.push(b);
    }
    output.push(table[idx].ext);
    *first_byte = output[dst_pos];
    table[idx].len = (plen + 1) as u16;
    table[idx].pos = dst_pos;
    Ok(())
}

// ======================================================================
// Encoder
// ======================================================================

/// Hash table size for the encoder's string table (load factor 0.5).
const HASHTAB_SIZE: usize = 1 << (MAX_BITS + 1);
/// Knuth's multiplicative hash constant.
const HASH_MUL: u32 = 2_654_435_761;

/// Hash table entry mapping (prefix_code, ext_byte) to a dictionary code.
#[derive(Clone, Copy)]
struct HashEnt {
    prefix: u16,
    ext: u8,
    code: u16,
}

/// Compress data with ZIP Method 1 (Shrinking).
pub(super) fn shrink(input: &[u8]) -> Vec<u8> {
    let mut table = vec![
        HashEnt {
            prefix: INVALID_CODE,
            ext: 0,
            code: 0,
        };
        HASHTAB_SIZE
    ];
    let mut queue = CodeQueue::new();
    let mut out = BitWriter::new();
    let mut code_size = INIT_BITS;

    if input.is_empty() {
        return Vec::new();
    }

    let mut curr = input[0] as u16;
    for &ext_byte in &input[1..] {
        let next = htab_find(&table, curr, ext_byte);
        if next != INVALID_CODE {
            curr = next;
            continue;
        }

        write_code(&mut out, curr, &mut code_size);

        let mut new_code = queue.pop();
        if new_code == INVALID_CODE {
            // Free leaf codes and notify the decoder.
            enc_partial_clear(&mut table, &mut queue);
            out.write_bits(CONTROL_CODE as u32, code_size);
            out.write_bits(PARTIAL_CLEAR as u32, code_size);
            new_code = queue.pop();
        }
        if new_code != INVALID_CODE {
            htab_insert(&mut table, curr, ext_byte, new_code);
        }

        curr = ext_byte as u16;
    }
    write_code(&mut out, curr, &mut code_size);
    out.finish()
}

/// Write a code, emitting INC_CODE_SIZE control codes as needed.
fn write_code(out: &mut BitWriter, code: u16, code_size: &mut u32) {
    while code as u32 > (1u32 << *code_size) - 1 {
        out.write_bits(CONTROL_CODE as u32, *code_size);
        out.write_bits(INC_CODE_SIZE as u32, *code_size);
        *code_size += 1;
    }
    out.write_bits(code as u32, *code_size);
}

/// Partial clear (encoder side): drop entries whose code is not used as a
/// prefix and refill the free-code queue in increasing order.
fn enc_partial_clear(table: &mut [HashEnt], queue: &mut CodeQueue) {
    let mut is_prefix = [false; DICT_SIZE];
    for e in table.iter() {
        if e.prefix != INVALID_CODE {
            is_prefix[e.prefix as usize] = true;
        }
    }
    let mut new_table = vec![
        HashEnt {
            prefix: INVALID_CODE,
            ext: 0,
            code: 0,
        };
        HASHTAB_SIZE
    ];
    for e in table.iter() {
        if e.prefix == INVALID_CODE || !is_prefix[e.code as usize] {
            continue;
        }
        htab_insert(&mut new_table, e.prefix, e.ext, e.code);
    }
    table.copy_from_slice(&new_table);

    let mut codes = Vec::with_capacity(DICT_SIZE - FIRST_CODE as usize + 1);
    for i in FIRST_CODE..=MAX_CODE {
        if !is_prefix[i as usize] {
            codes.push(i);
        }
    }
    codes.push(INVALID_CODE);
    queue.codes = codes;
    queue.head = 0;
}

/// Hash of a (prefix_code, ext_byte) key.
fn htab_hash(code: u16, byte: u8) -> usize {
    (((((byte as u32) << 16) | code as u32).wrapping_mul(HASH_MUL)) >> (32 - 14)) as usize
}

/// Look up the code for (prefix, ext); INVALID_CODE when absent.
fn htab_find(table: &[HashEnt], prefix: u16, ext: u8) -> u16 {
    let mut i = htab_hash(prefix, ext);
    loop {
        let e = table[i];
        if e.prefix == INVALID_CODE {
            return INVALID_CODE;
        }
        if e.prefix == prefix && e.ext == ext {
            return e.code;
        }
        i = (i + 1) % HASHTAB_SIZE;
    }
}

/// Insert (prefix, ext) -> code. The key must not already exist.
fn htab_insert(table: &mut [HashEnt], prefix: u16, ext: u8, code: u16) {
    let mut i = htab_hash(prefix, ext);
    while table[i].prefix != INVALID_CODE {
        i = (i + 1) % HASHTAB_SIZE;
    }
    table[i] = HashEnt { prefix, ext, code };
}

// ======================================================================
// Bit-level I/O (LSB-first)
// ======================================================================

/// LSB-first bitstream reader.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Read `count` bits; returns `None` past the end of input.
    fn try_read_bits(&mut self, count: u32) -> Option<u32> {
        if count == 0 {
            return Some(0);
        }
        if self.bit_pos + count as usize > self.data.len() * 8 {
            return None;
        }
        let mut result = 0u32;
        for i in 0..count as usize {
            let idx = self.bit_pos + i;
            if (self.data[idx / 8] >> (idx % 8)) & 1 != 0 {
                result |= 1 << i;
            }
        }
        self.bit_pos += count as usize;
        Some(result)
    }
}

/// LSB-first bitstream writer.
struct BitWriter {
    buf: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            bit_pos: 0,
        }
    }

    /// Write the low `count` bits of `value`, LSB-first.
    fn write_bits(&mut self, value: u32, count: u32) {
        for i in 0..count as usize {
            let idx = self.bit_pos + i;
            if idx / 8 == self.buf.len() {
                self.buf.push(0);
            }
            if (value >> i) & 1 != 0 {
                self.buf[idx / 8] |= 1 << (idx % 8);
            }
        }
        self.bit_pos += count as usize;
    }

    /// Return the byte buffer, zero-padding the final partial byte.
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn roundtrip_literals() {
        let data = b"Hello, world! This is a shrinking test.";
        let compressed = shrink(data);
        assert_eq!(unshrink(&compressed).unwrap(), data);
    }

    #[test]
    fn roundtrip_repetitive() {
        // Highly repetitive data exercises dictionary codes and KwKwK.
        let mut data = Vec::new();
        for _ in 0..500 {
            data.extend_from_slice(b"ABABAB");
        }
        let compressed = shrink(&data);
        assert!(compressed.len() < data.len() / 4);
        assert_eq!(unshrink(&compressed).unwrap(), data);
    }

    #[test]
    fn roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255).cycle().take(256 * 40).collect();
        let compressed = shrink(&data);
        assert_eq!(unshrink(&compressed).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        assert_eq!(shrink(b""), Vec::<u8>::new());
        assert_eq!(unshrink(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_single_byte() {
        let compressed = shrink(b"X");
        assert_eq!(unshrink(&compressed).unwrap(), b"X");
    }

    #[test]
    fn roundtrip_code_width_growth() {
        // Enough distinct pairs to grow the dictionary past 9..13 bit widths.
        let mut data = Vec::new();
        let mut state = 1u32;
        for _ in 0..200_000 {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            data.push((state >> 16) as u8);
        }
        // Sprinkle repetition so dictionary codes are actually emitted.
        for b in data.iter_mut().step_by(997) {
            *b = b'A';
        }
        let compressed = shrink(&data);
        assert_eq!(unshrink(&compressed).unwrap(), data);
    }

    #[test]
    fn roundtrip_partial_clear() {
        // Force the dictionary to fill (8192 entries) so a partial clear
        // occurs; pseudo-random input creates many distinct strings.
        let mut data = Vec::new();
        let mut state = 7u32;
        for _ in 0..300_000 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push(((state >> 16) & 0xff) as u8);
        }
        let compressed = shrink(&data);
        assert_eq!(unshrink(&compressed).unwrap(), data);
    }

    #[test]
    fn unshrink_first_code_must_be_literal() {
        // The first non-control code must be a literal byte (0-255).
        let mut w = BitWriter::new();
        w.write_bits(257, 9);
        let buf = w.finish();
        assert!(unshrink(&buf).is_err());
        // Leading control codes are consumed transparently; a stream of
        // only control codes decodes to empty output.
        let mut w = BitWriter::new();
        w.write_bits(CONTROL_CODE as u32, 9);
        w.write_bits(INC_CODE_SIZE as u32, 9);
        let buf = w.finish();
        assert_eq!(unshrink(&buf).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unshrink_invalid_control_subcode() {
        let mut w = BitWriter::new();
        w.write_bits(b'A' as u32, 9);
        w.write_bits(CONTROL_CODE as u32, 9);
        w.write_bits(7, 9); // invalid sub-code
        let buf = w.finish();
        assert!(unshrink(&buf).is_err());
    }

    #[test]
    fn unshrink_truncated() {
        let data = b"some reasonably long input for truncation testing";
        let compressed = shrink(data);
        // Truncated input must not panic; it just decodes what it can.
        let _ = unshrink(&compressed[..compressed.len() / 2]);
    }

    #[test]
    fn unshrink_manual_literals() {
        // Two literal codes 'H' 'i' at 9 bits.
        let mut w = BitWriter::new();
        w.write_bits(b'H' as u32, 9);
        w.write_bits(b'i' as u32, 9);
        let buf = w.finish();
        assert_eq!(unshrink(&buf).unwrap(), b"Hi");
    }

    #[test]
    fn unshrink_manual_dict_and_kwkwk() {
        // Codes: 'A', 'A', 257 → output "AAAA" (257 = "AA" via KwKwK-ish use).
        let mut w = BitWriter::new();
        w.write_bits(b'A' as u32, 9);
        w.write_bits(b'A' as u32, 9);
        w.write_bits(257, 9);
        let buf = w.finish();
        assert_eq!(unshrink(&buf).unwrap(), b"AAAA");
    }
}
