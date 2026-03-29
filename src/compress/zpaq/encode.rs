//! ZPAQ encoding (public API).
//!
//! Produces a single-payload ZPAQ block using the crate's built-in model
//! levels 1, 2, or 3.
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
use super::models::{self, ModelConfig};
use super::predictor::Predictor;
use super::zpaql::ZPAQL;

const HEADER_METADATA_SIZE: usize = 4;

/// Validated custom ZPAQ model for the low-level public encoder.
#[derive(Debug, Clone)]
pub struct CustomModel {
    level_byte: u8,
    comp_config: Vec<u8>,
    hcomp: Vec<u8>,
    hh: usize,
    hm: usize,
}

impl CustomModel {
    /// Build a validated custom model.
    pub fn new(
        level_byte: u8,
        hh: usize,
        hm: usize,
        comp_config: Vec<u8>,
        hcomp: Vec<u8>,
    ) -> Result<Self, Error> {
        validate_custom_model(hh, hm, &comp_config, &hcomp)?;
        Ok(Self {
            level_byte,
            comp_config,
            hcomp,
            hh,
            hm,
        })
    }

    pub(crate) const fn level_byte(&self) -> u8 {
        self.level_byte
    }

    pub(crate) fn as_model_config(&self) -> ModelConfig {
        ModelConfig {
            comp_config: self.comp_config.clone(),
            hcomp: self.hcomp.clone(),
            hh: self.hh,
            hm: self.hm,
        }
    }
}

fn write_terminated_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
    output.push(0);
}

pub(crate) fn write_block_header(output: &mut Vec<u8>, level: u32) -> models::ModelConfig {
    let level = level.clamp(1, 3);
    let config = models::model_config(level);
    write_block_header_for_config(output, level as u8, &config);
    config
}

pub(crate) fn write_block_header_for_custom_model(
    output: &mut Vec<u8>,
    model: &CustomModel,
) -> models::ModelConfig {
    let config = model.as_model_config();
    write_block_header_for_config(output, model.level_byte(), &config);
    config
}

fn write_block_header_for_config(output: &mut Vec<u8>, level_byte: u8, config: &ModelConfig) {
    // ── Block header ────────────────────────────────────────────
    // Magic: "zPQ"
    output.extend_from_slice(b"zPQ");
    // Level (1 byte)
    output.push(level_byte);

    // Header size counts bytes from `hh` through the end of HCOMP:
    // hh(1) + hm(1) + comp_config(count+defs) + hcomp_len(2) + hcomp bytes.
    let hsize = config.comp_config.len() + config.hcomp.len() + HEADER_METADATA_SIZE;
    output.extend_from_slice(&(hsize as u16).to_le_bytes());

    output.push(config.hh as u8);
    output.push(config.hm as u8);
    output.push(config.comp_config[0]);
    output.extend_from_slice(&config.comp_config[1..]);
    output.extend_from_slice(&(config.hcomp.len() as u16).to_le_bytes());
    output.extend_from_slice(&config.hcomp);
}

pub(crate) fn encode_segment(
    output: &mut Vec<u8>,
    config: &models::ModelConfig,
    filename: &[u8],
    comment: &[u8],
    input: &[u8],
) {
    // ── Segment header ──────────────────────────────────────────
    write_terminated_bytes(output, filename);
    write_terminated_bytes(output, comment);

    // ── Compress data ───────────────────────────────────────────
    let z = ZPAQL::new(config.hh, config.hm, config.hcomp.clone());
    let mut pred = Predictor::new(z, &config.comp_config);
    let mut enc = ArithEncoder::new();

    for &byte in input {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            let prob = pred.predict();
            enc.encode(bit, prob);
            pred.update(bit);
        }
    }

    let compressed = enc.finish();

    output.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    output.extend_from_slice(&compressed);
    output.extend_from_slice(&(input.len() as u32).to_le_bytes());

    // ── Segment end ─────────────────────────────────────────────
    output.push(0xFF);
}

/// Compress data using ZPAQ at the given built-in level (1-3).
///
/// Level 1 is fastest with least compression.
/// Level 3 is slowest with best compression.
///
/// Values outside this range are clamped because the public encoder currently
/// only exposes the crate's built-in level 1-3 model set, even though the
/// decoder accepts arbitrary valid upstream model headers.
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
    let mut output = Vec::new();
    let config = write_block_header(&mut output, level);
    encode_segment(&mut output, &config, b"", b"", input);

    // ── Block end ───────────────────────────────────────────────
    // No more segments marker: 0xFF
    output.push(0xFF);

    output
}

/// Compress data using a validated custom ZPAQ model.
pub fn encode_with_model(input: &[u8], model: &CustomModel) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let config = write_block_header_for_custom_model(&mut output, model);
    encode_segment(&mut output, &config, b"", b"", input);
    output.push(0xFF);
    Ok(output)
}

fn validate_custom_model(
    hh: usize,
    hm: usize,
    comp_config: &[u8],
    hcomp: &[u8],
) -> Result<(), Error> {
    let max_shift = usize::BITS as usize - 1;
    if hh > max_shift || hm > max_shift {
        return Err(Error::InvalidData("zpaq: invalid memory size"));
    }
    ZPAQL::validate_hcomp(hcomp)?;
    let z = ZPAQL::new(hh, hm, hcomp.to_vec());
    let _predictor = Predictor::try_new(z, comp_config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_hsize_is_canonical() {
        let compressed = encode(b"hello", 1);
        let hsize = u16::from_le_bytes([compressed[4], compressed[5]]) as usize;
        let config = models::model_config(1);
        assert_eq!(
            hsize,
            config.comp_config.len() + config.hcomp.len() + HEADER_METADATA_SIZE
        );
    }

    #[test]
    fn test_encode_clamps_level_range() {
        let low = encode(b"hello", 0);
        let high = encode(b"hello", 99);
        assert_eq!(low[3], 1);
        assert_eq!(high[3], 3);
    }

    #[test]
    fn test_encode_with_custom_model_roundtrip() {
        let builtin = models::model_config(1);
        let model = CustomModel::new(
            42,
            builtin.hh,
            builtin.hm,
            builtin.comp_config.clone(),
            builtin.hcomp.clone(),
        )
        .unwrap();
        let encoded = encode_with_model(b"hello custom", &model).unwrap();
        assert_eq!(encoded[3], 42);
        let decoded = crate::compress::zpaq::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, b"hello custom");
    }

    #[test]
    fn test_custom_model_rejects_invalid_memory_size() {
        let builtin = models::model_config(1);
        assert!(matches!(
            CustomModel::new(
                1,
                usize::BITS as usize,
                builtin.hm,
                builtin.comp_config.clone(),
                builtin.hcomp.clone(),
            ),
            Err(Error::InvalidData("zpaq: invalid memory size"))
        ));
    }
}
