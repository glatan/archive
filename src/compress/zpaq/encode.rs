//! ZPAQ encoding (public API).
//!
//! Emits the canonical upstream ZPAQ stream layout: a 13-byte locator
//! tag followed by `zPQ`, the format-level byte (`1` for modeled
//! streams, `2` for unmodeled), the type byte `1`, and the serialized
//! ZPAQL header.  Each segment is `1 filename 0 comment 0 0` followed
//! by the arithmetic-coded payload — starting with a postprocessor
//! selector (`0` = PASS for built-in models), then 8 modeled bits per
//! byte — and ends with the arithmetic-coded EOS bit, four zero bytes,
//! and `253` + 20-byte SHA-1 of the postprocessed segment data.
//!
//! This module writes a single block per call; multi-segment blocks
//! share predictor and arithmetic state exactly like upstream
//! `Compressor`, so [`BlockEncoder`] must be reused across segments of
//! the same block.
//!
//! # Examples
//!
//! ```
//! use archive::compress::zpaq::{decode, encode};
//!
//! let data = b"Hello, ZPAQ!";
//! let compressed = encode::encode(data, 1);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::error::Error;

use super::arithmetic::ArithEncoder;
use super::models;
use super::predictor::Predictor;
use super::zpaql::Zpaql;

/// 13-byte locator tag preceding `zPQ` in upstream ZPAQ files
/// (written by the zpaq CLI; scanned for by `Decompresser::findBlock`).
pub(crate) const ZPAQ_TAG: [u8; 13] = [
    0x37, 0x6b, 0x53, 0x74, 0xa0, 0x31, 0x83, 0xd3, 0x8c, 0xb2, 0x28, 0xb0, 0xd3,
];

/// Validated custom ZPAQ model for the low-level public encoder.
///
/// `comp_config` uses upstream component numbering
/// (`1=CONST, 2=CM, 3=ICM, 4=MATCH, 5=AVG, 6=MIX2, 7=MIX, 8=ISSE, 9=SSE`)
/// and holds `n` followed by `n` COMP records (no terminator).
/// `hcomp` is the HCOMP opcode stream without the trailing `0`.
#[derive(Debug, Clone)]
pub struct CustomModel {
    level_byte: u8,
    z: Zpaql,
    pcomp: Option<Vec<u8>>,
}

impl CustomModel {
    /// Build a validated custom model.
    ///
    /// `level_byte` is the wire format level: `1` requires at least one
    /// predictor component; `2` also allows unmodeled (`n == 0`)
    /// streams. Other values are rejected because upstream decoders
    /// refuse them.
    pub fn new(
        level_byte: u8,
        hh: usize,
        hm: usize,
        comp_config: Vec<u8>,
        hcomp: Vec<u8>,
    ) -> Result<Self, Error> {
        if hh > 32 || hm > 32 {
            return Err(Error::InvalidData("zpaq: invalid memory size"));
        }
        let mut comp = Vec::with_capacity(comp_config.len() + 4);
        comp.push(hh as u8);
        comp.push(hm as u8);
        comp.push(0); // ph
        comp.push(0); // pm
        comp.extend_from_slice(&comp_config);
        let z = Zpaql::set_header(&comp, &hcomp)?;
        match level_byte {
            1 if z.component_count() == 0 => {
                return Err(Error::InvalidData(
                    "zpaq: level 1 requires at least 1 component",
                ));
            }
            1 | 2 => {}
            _ => {
                return Err(Error::InvalidData("zpaq: level byte must be 1 or 2"));
            }
        }
        // Exercise component allocation/table validation now.
        let _ = Predictor::new(z.clone())?;
        Ok(Self {
            level_byte,
            z,
            pcomp: None,
        })
    }

    /// Attach a PCOMP postprocessor program, matching upstream
    /// `Compressor::postProcess` + `startBlock(config, args, pcomp)`:
    /// the first segment of the block carries `1` + a 2-byte program
    /// length + `pcomp`, and `ph`/`pm` are emitted in the block
    /// header as the PCOMP memory sizes (each at most 32).
    ///
    /// The input to [`encode_with_model`] is the *preimage*: decoding
    /// applies `pcomp` to the decompressed bytes, so callers must
    /// supply data that `pcomp` transforms into the desired output
    /// (upstream uses external preprocessors such as E8E9 for this).
    /// The stored SHA-1 covers the postprocessed output, as upstream
    /// `verify` mode computes it.
    ///
    /// The program is validated by running it through the PCOMP VM
    /// once with bounded cycles; programs that fail to halt are
    /// rejected.
    pub fn with_pcomp(mut self, ph: u8, pm: u8, pcomp: Vec<u8>) -> Result<Self, Error> {
        if ph > 32 || pm > 32 {
            return Err(Error::InvalidData("zpaq: invalid PCOMP memory size"));
        }
        if pcomp.is_empty() || pcomp.len() > 0xFFFF {
            return Err(Error::InvalidData("zpaq: invalid PCOMP length"));
        }
        let mut pz = Zpaql::set_pcomp_header(ph, pm, &pcomp)?;
        pz.initp()?;
        pz.run(0)?;
        self.z.set_pcomp_mem(ph, pm);
        self.pcomp = Some(pcomp);
        Ok(self)
    }
}

/// Streaming encoder for one ZPAQ block.
///
/// Mirrors upstream `Compressor` state sharing: the predictor and
/// arithmetic coder initialize once per block and carry their state
/// across every segment, so segments of one block must be emitted
/// through the same `BlockEncoder`.
pub(crate) struct BlockEncoder {
    /// Header + VM template (cloned into each predictor).
    z: Zpaql,
    /// Wire level byte (`1` modeled, `2` unmodeled).
    level: u8,
    enc: ArithEncoder,
    /// Persistent predictor, created at the first segment.
    pred: Option<Predictor>,
    /// Whether the first segment's `enc.init()`/postprocessor
    /// selector ran.
    started: bool,
    /// PCOMP program emitted as a PROG selector on the first segment
    /// (upstream `postProcess`).
    pcomp: Option<Vec<u8>>,
    /// PCOMP VM running over the compressed payload to hash the
    /// postprocessed output (upstream `verify` mode: `pz.sha1`).
    /// Persists across the block's segments.
    pz: Option<Zpaql>,
    /// SHA-1 of the current segment's postprocessed data.
    sha1: crate::util::sha1::Sha1,
}

impl BlockEncoder {
    /// Create a block encoder from a parsed header.
    ///
    /// `level` must be consistent with the model: `1` requires `n > 0`.
    pub(crate) fn new(z: Zpaql, level: u8) -> Result<Self, Error> {
        if !(1..=2).contains(&level) {
            return Err(Error::InvalidData("zpaq: level byte must be 1 or 2"));
        }
        if level == 1 && z.component_count() == 0 {
            return Err(Error::InvalidData(
                "zpaq: level 1 requires at least 1 component",
            ));
        }
        Ok(Self {
            z,
            level,
            enc: ArithEncoder::new(),
            pred: None,
            started: false,
            pcomp: None,
            pz: None,
            sha1: crate::util::sha1::Sha1::new(),
        })
    }

    /// Write `tag "zPQ" level 1 header` to `out`.
    pub(crate) fn write_block_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&ZPAQ_TAG);
        out.extend_from_slice(b"zPQ");
        out.push(self.level);
        out.push(1);
        self.z.write_header(out);
    }

    /// Write a complete segment: header, coded data, EOS, checksum.
    ///
    /// Equivalent to upstream `startSegment` + `compress` +
    /// `endSegmentChecksum`.  On the first segment of the block this
    /// also emits the PASS postprocessor selector.
    pub(crate) fn encode_segment(
        &mut self,
        out: &mut Vec<u8>,
        filename: &[u8],
        comment: &[u8],
        data: &[u8],
    ) -> Result<(), Error> {
        out.push(1);
        out.extend_from_slice(filename);
        out.push(0);
        out.extend_from_slice(comment);
        out.push(0);
        out.push(0); // reserved byte
        if !self.started {
            // Upstream `postProcess`: initialize coder+predictor at the
            // first segment, then arithmetic-code the postprocessor
            // selector (`0` = PASS, or `1` + 2-byte length + program
            // for PROG). The selector appears only on a block's first
            // segment; the loaded program applies to the whole block.
            let pred = Predictor::new(self.z.clone())?;
            if !pred.is_modeled() {
                self.enc.init_stored();
            }
            self.pred = Some(pred);
            self.started = true;
            if let Some(prog) = self.pcomp.clone() {
                self.compress_byte(1)?;
                self.compress_byte((prog.len() & 0xff) as i32)?;
                self.compress_byte(((prog.len() >> 8) & 0xff) as i32)?;
                for &b in &prog {
                    self.compress_byte(i32::from(b))?;
                }
                let (ph, pm) = self.z.pcomp_mem();
                let mut pz = Zpaql::set_pcomp_header(ph, pm, &prog)?;
                pz.initp()?;
                self.pz = Some(pz);
            } else {
                self.compress_byte(0)?;
            }
        }
        // Upstream `verify` mode: the stored checksum covers the
        // postprocessed output, so feed the payload through the PCOMP
        // VM (including the end-of-segment run) when one is attached.
        self.sha1 = crate::util::sha1::Sha1::new();
        if self.pz.is_some() {
            let mut pz = self.pz.take().expect("checked");
            let mut processed = Vec::with_capacity(data.len());
            for &b in data {
                self.compress_byte(i32::from(b))?;
                pz.run(u32::from(b))?;
                processed.extend_from_slice(&pz.take_output());
            }
            self.compress_byte(-1)?;
            pz.run(u32::MAX)?;
            processed.extend_from_slice(&pz.take_output());
            self.sha1.update(&processed);
            self.pz = Some(pz);
        } else {
            self.sha1.update(data);
            for &b in data {
                self.compress_byte(i32::from(b))?;
            }
            // EOS
            self.compress_byte(-1)?;
        }
        out.extend_from_slice(&self.enc.take());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.push(253);
        out.extend_from_slice(&self.sha1.clone().finish());
        Ok(())
    }

    /// Upstream `Encoder::compress`: one byte or `-1` for end of
    /// segment.
    fn compress_byte(&mut self, c: i32) -> Result<(), Error> {
        let pred = self.pred.as_mut().expect("initialized");
        if pred.is_modeled() {
            if c < 0 {
                self.enc.encode(1, 0);
            } else {
                let c = c as u32;
                debug_assert!(c < 256);
                self.enc.encode(0, 0);
                for i in (0..8).rev() {
                    let p = (pred.predict() * 2 + 1) as u32;
                    debug_assert!(p > 0 && p < 65536);
                    let y = (c >> i) & 1;
                    self.enc.encode(y, p);
                    pred.update(y)?;
                }
            }
        } else {
            self.enc.store(if c < 0 { None } else { Some(c as u8) });
        }
        Ok(())
    }
}

/// Compress data using ZPAQ at the given built-in level (1-3).
///
/// Level 1 is fastest with least compression.
/// Level 3 is slowest with best compression.
///
/// Values outside this range are clamped because the public encoder
/// exposes the crate's built-in level 1-3 model set.
///
/// # Examples
///
/// ```
/// use archive::compress::zpaq::{decode, encode};
///
/// let data = b"Hello, ZPAQ!";
/// let compressed = encode::encode(data, 1);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8], level: u32) -> Vec<u8> {
    let level = level.clamp(1, 3);
    let z = models::model_zpaql(level).expect("built-in model headers are valid");
    let wire_level = 1 + u8::from(z.component_count() == 0);
    let mut block =
        BlockEncoder::new(z, wire_level).expect("built-in model headers produce valid blocks");
    let mut output = Vec::new();
    block.write_block_header(&mut output);
    block
        .encode_segment(&mut output, b"", b"", input)
        .expect("built-in models encode infallibly");
    output.push(255); // end of block
    output
}

/// Compress data using a validated custom ZPAQ model.
pub fn encode_with_model(input: &[u8], model: &CustomModel) -> Result<Vec<u8>, Error> {
    let mut block = BlockEncoder::new(model.z.clone(), model.level_byte)?;
    block.pcomp = model.pcomp.clone();
    let mut output = Vec::new();
    block.write_block_header(&mut output);
    block.encode_segment(&mut output, b"", b"", input)?;
    output.push(255);
    Ok(output)
}
