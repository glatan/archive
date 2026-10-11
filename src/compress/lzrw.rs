//! Shared framing for the LZRW family (LZRW1, LZRW1-A, LZRW2, LZRW3, LZRW3-A).
//!
//! Every family member uses the same container: a 4-byte copy flag followed
//! by a remainder. If the flag is [`FLAG_COPY`] the remainder is the data
//! verbatim; if it is [`FLAG_COMPRESS`] the remainder is a sequence of groups.
//! Each group carries a 16-bit control word (LSB first, bit i describing
//! item i: 0 = literal, 1 = copy) followed by up to sixteen items.
//!
//! A literal item is a single byte. A copy item is two bytes `C1 C2`: the
//! length is `C1[0..3]` plus a per-variant bias (1 for LZRW1, 3 for the
//! others), and `C1[4..7]*256 + C2` is a 12-bit field whose meaning differs
//! per variant (history offset, phrase-table index, or hash-table index).
//!
//! The shared `hash3` arithmetic and `START_STRING_18` constant are adopted
//! verbatim from Ross N. Williams' public-domain LZRW reference sources
//! (see THIRD_PARTY_NOTICES, "LZRW1 / LZRW2 / LZRW3 / LZRW3-A").

use crate::error::Error;
use alloc::vec::Vec;

pub(crate) const FLAG_BYTES: usize = 4;
pub(crate) const FLAG_COMPRESS: u8 = 0;
pub(crate) const FLAG_COPY: u8 = 1;
const ITEMS_PER_GROUP: usize = 16;

/// The 18-byte constant string that LZRW2/LZRW3/LZRW3-A point their tables
/// at during initialization so early items have a defined reference.
#[cfg(any(feature = "lzrw2", feature = "lzrw3", feature = "lzrw3a"))]
pub(crate) const START_STRING_18: &[u8; 18] = b"123456789012345678";

/// Result of reading the 4-byte copy flag.
pub(crate) enum Head {
    /// `FLAG_COPY`: everything after the flag is stored verbatim.
    Verbatim,
    /// `FLAG_COMPRESS`: group items follow.
    Compressed,
}

/// Read and validate the copy flag of a non-empty stream.
pub(crate) fn head(input: &[u8], errs: FlagErrs) -> Result<Head, Error> {
    debug_assert!(!input.is_empty());
    if input.len() < FLAG_BYTES {
        return Err(Error::InvalidData(errs.truncated_flag));
    }
    match input[0] {
        FLAG_COPY => Ok(Head::Verbatim),
        FLAG_COMPRESS => Ok(Head::Compressed),
        _ => Err(Error::InvalidData(errs.unknown_flag)),
    }
}

/// Per-variant error strings used by [`head`].
#[derive(Clone, Copy)]
pub(crate) struct FlagErrs {
    pub truncated_flag: &'static str,
    pub unknown_flag: &'static str,
}

/// A single item inside a group.
pub(crate) enum Item {
    Literal(u8),
    /// `len` already includes the variant's length bias; `index` is the
    /// 12-bit field `C1[4..7]*256 + C2` whose meaning is variant-specific.
    Copy {
        len: usize,
        index: usize,
    },
}

/// Iterator over the items of a `FLAG_COMPRESS` stream body.
///
/// Mirrors the reference decoders' end-of-stream behaviour: a final group
/// may be partial, and when the data runs out mid-group the remaining
/// control bits are simply ignored. A copy item truncated after its first
/// byte (one byte available) is an error.
pub(crate) struct Items<'a> {
    input: &'a [u8],
    pos: usize,
    control: u16,
    mask: u16,
    len_bias: usize,
    truncated_copy: &'static str,
}

impl<'a> Items<'a> {
    /// `input` is the whole stream including the flag bytes; iteration
    /// starts at the first group. `len_bias` is 1 for LZRW1, 3 otherwise.
    pub(crate) fn new(input: &'a [u8], len_bias: usize, truncated_copy: &'static str) -> Self {
        Self {
            input,
            pos: FLAG_BYTES,
            control: 0,
            mask: 0,
            len_bias,
            truncated_copy,
        }
    }

    /// Return the next item, or `None` at end of stream.
    pub(crate) fn next(&mut self) -> Result<Option<Item>, Error> {
        if self.mask == 0 {
            if self.pos + 2 > self.input.len() {
                return Ok(None);
            }
            self.control = u16::from_le_bytes([self.input[self.pos], self.input[self.pos + 1]]);
            self.pos += 2;
            self.mask = 1;
        }
        // Data exhausted mid-group: the trailing control bits are ignored.
        if self.pos >= self.input.len() {
            return Ok(None);
        }
        let item = if self.control & self.mask == 0 {
            let b = self.input[self.pos];
            self.pos += 1;
            Item::Literal(b)
        } else {
            if self.pos + 2 > self.input.len() {
                return Err(Error::InvalidData(self.truncated_copy));
            }
            let c1 = self.input[self.pos] as usize;
            let c2 = self.input[self.pos + 1] as usize;
            self.pos += 2;
            Item::Copy {
                len: (c1 & 0x0f) + self.len_bias,
                index: (c1 >> 4) * 256 + c2,
            }
        };
        self.mask = self.mask.wrapping_shl(1);
        Ok(Some(item))
    }
}

/// Encoder-side group buffering.
///
/// Reserves the 2-byte control word at the start of each group and patches
/// it when the group closes (16 items or `finish`). A trailing group left
/// with zero items is dropped, matching the reference encoders.
pub(crate) struct GroupEncoder {
    out: Vec<u8>,
    ctrl_pos: usize,
    control: u16,
    items: usize,
}

impl GroupEncoder {
    /// Start a new stream: writes the copy flag and reserves the first
    /// control word.
    pub(crate) fn new() -> Self {
        let mut enc = Self {
            out: Vec::with_capacity(FLAG_BYTES + 2),
            ctrl_pos: 0,
            control: 0,
            items: 0,
        };
        enc.out.extend_from_slice(&[FLAG_COMPRESS, 0, 0, 0]);
        enc.start_group();
        enc
    }

    fn seal_group(&mut self) {
        self.out[self.ctrl_pos] = (self.control & 0xff) as u8;
        self.out[self.ctrl_pos + 1] = (self.control >> 8) as u8;
    }

    fn start_group(&mut self) {
        self.ctrl_pos = self.out.len();
        self.out.extend_from_slice(&[0, 0]);
        self.control = 0;
        self.items = 0;
    }

    fn end_item(&mut self) {
        self.items += 1;
        if self.items == ITEMS_PER_GROUP {
            self.seal_group();
            self.start_group();
        }
    }

    /// Emit a literal item.
    pub(crate) fn literal(&mut self, b: u8) {
        self.out.push(b);
        self.end_item();
    }

    /// Emit a copy item: `len_field` is the raw 4-bit length field
    /// (`len - len_bias`) and `index` the 12-bit second field.
    pub(crate) fn copy(&mut self, len_field: usize, index: usize) {
        debug_assert!(len_field < 16 && index < 4096);
        self.control |= 1 << self.items;
        self.out
            .push((((index >> 8) & 0x0f) << 4 | len_field) as u8);
        self.out.push((index & 0xff) as u8);
        self.end_item();
    }

    /// Close the stream and return the compressed bytes.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        self.seal_group();
        if self.items == 0 {
            // The last group carried no items: drop its control word.
            self.out.truncate(self.ctrl_pos);
        }
        self.out
    }
}

/// The verbatim (`FLAG_COPY`) representation of `input`.
pub(crate) fn verbatim(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FLAG_BYTES + input.len());
    out.extend_from_slice(&[FLAG_COPY, 0, 0, 0]);
    out.extend_from_slice(input);
    out
}

/// Copy `len` bytes starting at absolute output position `pos`, allowing
/// the copy to overlap the bytes being produced (LZ77-style).
pub(crate) fn copy_from_output(out: &mut Vec<u8>, pos: usize, len: usize) {
    for i in 0..len {
        let b = out[pos + i];
        out.push(b);
    }
}

/// The LZRW2/LZRW3/LZRW3-A three-byte hash used by each compressor (and by the
/// LZRW3/LZRW3-A decompressor table updates): `((40543 * ((b0<<8) ^ (b1<<4) ^ b2)) >> 4) & mask`.
///
/// `mask` selects the value range: `0xFFF` yields a 12-bit index (LZRW3),
/// `0x1FF` yields a partition number that must be shifted left by the
/// depth bits (LZRW3-A). Returns the raw masked value.
#[cfg(any(feature = "lzrw2", feature = "lzrw3", feature = "lzrw3a"))]
pub(crate) fn hash3(b: &[u8], mask: u32) -> usize {
    let v = ((b[0] as u32) << 8) ^ ((b[1] as u32) << 4) ^ b[2] as u32;
    ((40543u32.wrapping_mul(v) >> 4) & mask) as usize
}
