//! Shared PPMd var.H / PPMd7 codec.
//!
//! Ported from the `ppmd-rust` crate (CC0-1.0 OR MIT-0), itself derived
//! from 7-Zip's public-domain PPMd implementation (`Ppmd.h`, `Ppmd7.c`,
//! `Ppmd7Dec.c`, `Ppmd7Enc.c`), and adapted to this crate's
//! `no_std + alloc` style. See `THIRD_PARTY_NOTICES` section 3.
//! Decode refuses a model larger than 256 MiB. Encode still accepts the
//! format maximum (`u32::MAX - 36`).

use alloc::vec::Vec;

use crate::error::Error;

mod internal;

pub(crate) const PPMD7_MIN_ORDER: u32 = 2;
pub(crate) const PPMD7_MAX_ORDER: u32 = 64;
pub(crate) const PPMD7_MIN_MEM_SIZE: u32 = 2048;
pub(crate) const PPMD7_MAX_MEM_SIZE: u32 = u32::MAX - 36;
/// Decode refuses a model larger than 256 MiB. Encode keeps the format maximum.
pub(crate) const PPMD_DECODE_MEM_LIMIT: u32 = 1 << 28;
pub(crate) const SYM_END: i32 = -1;
pub(crate) const SYM_ERROR: i32 = -2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ppmd7Properties {
    pub(crate) order: u8,
    pub(crate) mem_size: u32,
}

impl Ppmd7Properties {
    pub(crate) fn new(order: u8, mem_size: u32) -> Result<Self, Error> {
        if !(PPMD7_MIN_ORDER..=PPMD7_MAX_ORDER).contains(&(order as u32)) {
            return Err(Error::InvalidData("ppmd: order must be in 2..=64"));
        }
        if !(PPMD7_MIN_MEM_SIZE..=PPMD7_MAX_MEM_SIZE).contains(&mem_size) {
            return Err(Error::InvalidData("ppmd: memory size out of range"));
        }
        Ok(Self { order, mem_size })
    }

    pub(crate) fn from_sevenz_properties(properties: &[u8]) -> Result<Self, Error> {
        if properties.len() != 5 {
            return Err(Error::InvalidData("7z: PPMd properties must be 5 bytes"));
        }
        Self::new(
            properties[0],
            u32::from_le_bytes([properties[1], properties[2], properties[3], properties[4]]),
        )
    }

    pub(crate) const fn to_sevenz_properties(self) -> [u8; 5] {
        let mem = self.mem_size.to_le_bytes();
        [self.order, mem[0], mem[1], mem[2], mem[3]]
    }
}

pub(crate) fn decode(
    input: &[u8],
    properties: Ppmd7Properties,
    unpacked_size: usize,
) -> Result<Vec<u8>, Error> {
    if unpacked_size > crate::util::bounded::DECLARED_OUTPUT_LIMIT {
        return Err(Error::OutputLimitExceeded {
            limit: crate::util::bounded::DECLARED_OUTPUT_LIMIT,
        });
    }
    let mut ppmd =
        internal::ppmd7::PPMd7::new_decoder(input, properties.order as u32, properties.mem_size)?;
    let mut output = Vec::with_capacity(unpacked_size);
    for _ in 0..unpacked_size {
        let symbol = ppmd.decode_symbol()?;
        if symbol < 0 {
            return Err(Error::InvalidData(
                "ppmd: unexpected end marker while decoding fixed-size stream",
            ));
        }
        output.push(symbol as u8);
    }
    Ok(output)
}

pub(crate) fn encode(
    input: &[u8],
    properties: Ppmd7Properties,
    with_end_marker: bool,
) -> Result<Vec<u8>, Error> {
    let mut ppmd =
        internal::ppmd7::PPMd7::new_encoder(properties.order as u32, properties.mem_size)?;
    for &byte in input {
        ppmd.encode_symbol(byte as i32)?;
    }
    if with_end_marker {
        ppmd.encode_symbol(SYM_END)?;
    }
    ppmd.flush_range_encoder();
    Ok(ppmd.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sevenz_properties() {
        let props = Ppmd7Properties::from_sevenz_properties(&[6, 0x00, 0x00, 0x10, 0x00]).unwrap();
        assert_eq!(props.order, 6);
        assert_eq!(props.mem_size, 0x0010_0000);
        assert_eq!(props.to_sevenz_properties(), [6, 0x00, 0x00, 0x10, 0x00]);
    }

    #[test]
    fn test_parse_sevenz_properties_rejects_invalid_length() {
        assert_eq!(
            Ppmd7Properties::from_sevenz_properties(&[6, 0, 0, 0]),
            Err(Error::InvalidData("7z: PPMd properties must be 5 bytes"))
        );
    }

    #[test]
    fn test_decode_rejects_model_above_256_mib() {
        for mem_size in [1 << 29, u32::MAX - 36] {
            let props = Ppmd7Properties::new(6, mem_size).unwrap();
            let err = decode(&[], props, 1).unwrap_err();
            assert_eq!(
                err,
                Error::Unsupported("ppmd: memory size exceeds decode limit")
            );
        }
    }

    #[test]
    fn test_roundtrip_without_end_marker() {
        let payload = b"Shared PPMd fixture\nShared PPMd fixture\n";
        let props = Ppmd7Properties::new(6, 1 << 20).unwrap();
        let encoded = encode(payload, props, false).unwrap();
        let decoded = decode(&encoded, props, payload.len()).unwrap();
        assert_eq!(decoded, payload);
    }
}
