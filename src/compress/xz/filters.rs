//! Shared xz block filter helpers.

use alloc::vec::Vec;

use crate::error::Error;

use super::registry::FilterRegistry;

/// xz Delta filter ID.
pub(crate) const FILTER_DELTA: u64 = 0x03;
/// xz x86 BCJ filter ID.
pub(crate) const FILTER_X86: u64 = 0x04;
/// xz PowerPC BCJ filter ID.
pub(crate) const FILTER_POWERPC: u64 = 0x05;
/// xz IA64 BCJ filter ID.
pub(crate) const FILTER_IA64: u64 = 0x06;
/// xz ARM BCJ filter ID.
pub(crate) const FILTER_ARM: u64 = 0x07;
/// xz ARM-Thumb BCJ filter ID.
pub(crate) const FILTER_ARMTHUMB: u64 = 0x08;
/// xz SPARC BCJ filter ID.
pub(crate) const FILTER_SPARC: u64 = 0x09;
/// xz ARM64 BCJ filter ID.
pub(crate) const FILTER_ARM64: u64 = 0x0A;
/// xz RISC-V BCJ filter ID.
pub(crate) const FILTER_RISCV: u64 = 0x0B;
/// xz LZMA2 filter ID.
pub(crate) const FILTER_LZMA2: u64 = 0x21;

/// First filter ID in the range reserved for implementation-dependent
/// internal use (xz-file-format.txt §3.1.5). Filter IDs in
/// `FILTER_ID_RESERVED_START..` must never appear in a List of Filter
/// Flags, so a stream carrying one is malformed data.
pub(crate) const FILTER_ID_RESERVED_START: u64 = 0x4000_0000_0000_0000;

/// Supported pre-LZMA2 xz block filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// x86 BCJ filter.
    X86 { start_offset: u32 },
    /// PowerPC BCJ filter.
    PowerPc { start_offset: u32 },
    /// IA64 BCJ filter.
    Ia64 { start_offset: u32 },
    /// SPARC BCJ filter.
    Sparc { start_offset: u32 },
    /// ARM BCJ filter.
    Arm { start_offset: u32 },
    /// ARM-Thumb BCJ filter.
    ArmThumb { start_offset: u32 },
    /// ARM64 BCJ filter.
    Arm64 { start_offset: u32 },
    /// RISC-V BCJ filter.
    RiscV { start_offset: u32 },
    /// Delta filter.
    Delta { distance: u16 },
    /// Unsupported custom/unknown filter retained from the xz header.
    Unknown { id: u64, properties: Vec<u8> },
}

impl Filter {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        match self {
            Self::X86 { .. } => Ok(()),
            Self::PowerPc { start_offset } => {
                if *start_offset % 4 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::Ia64 { start_offset } => {
                if *start_offset % 16 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::Sparc { start_offset } => {
                if *start_offset % 4 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::Arm { start_offset } => {
                if *start_offset % 4 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::ArmThumb { start_offset } => {
                if *start_offset % 2 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::Arm64 { start_offset } => {
                if *start_offset % 4 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::RiscV { start_offset } => {
                if *start_offset % 2 != 0 {
                    return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
                }
                Ok(())
            }
            Self::Delta { distance } if (1..=256).contains(distance) => Ok(()),
            Self::Delta { .. } => Err(Error::InvalidData("xz: delta distance must be 1..=256")),
            Self::Unknown { id, .. } if *id >= FILTER_ID_RESERVED_START => {
                Err(Error::InvalidData("xz: reserved filter ID (>= 2^62)"))
            }
            Self::Unknown { .. } => Ok(()),
        }
    }
}

pub(crate) fn apply_encoder_filters(
    input: &[u8],
    filters: &[Filter],
    registry: Option<&FilterRegistry>,
) -> Result<Vec<u8>, Error> {
    let mut output = input.to_vec();
    for filter in filters {
        filter.validate()?;
        output = match filter {
            Filter::X86 { start_offset } => {
                crate::compress::bcj::x86_encode(&output, *start_offset)
            }
            Filter::PowerPc { start_offset } => {
                crate::compress::bcj::powerpc_encode(&output, *start_offset)
            }
            Filter::Ia64 { start_offset } => {
                crate::compress::bcj::ia64_encode(&output, *start_offset)
            }
            Filter::Sparc { start_offset } => {
                crate::compress::bcj::sparc_encode(&output, *start_offset)
            }
            Filter::Arm { start_offset } => {
                crate::compress::bcj::arm_encode(&output, *start_offset)
            }
            Filter::ArmThumb { start_offset } => {
                crate::compress::bcj::armthumb_encode(&output, *start_offset)
            }
            Filter::Arm64 { start_offset } => {
                crate::compress::bcj::arm64_encode(&output, *start_offset)
            }
            Filter::RiscV { start_offset } => {
                crate::compress::bcj::riscv_encode(&output, *start_offset)
            }
            Filter::Delta { distance } => {
                crate::compress::delta::encode(&output, *distance as usize)?
            }
            Filter::Unknown { id, properties } => {
                if let Some(codec) = registry.and_then(|registry| registry.get(*id)) {
                    codec.encode(&output, properties)?
                } else {
                    return Err(Error::Unsupported("xz: unsupported custom/unknown filter"));
                }
            }
        };
    }
    Ok(output)
}

pub(crate) fn apply_decoder_filters(
    input: &[u8],
    filters: &[Filter],
    registry: Option<&FilterRegistry>,
) -> Result<Vec<u8>, Error> {
    let mut output = input.to_vec();
    for filter in filters.iter().rev() {
        filter.validate()?;
        output = match filter {
            Filter::X86 { start_offset } => {
                crate::compress::bcj::x86_decode(&output, *start_offset)
            }
            Filter::PowerPc { start_offset } => {
                crate::compress::bcj::powerpc_decode(&output, *start_offset)
            }
            Filter::Ia64 { start_offset } => {
                crate::compress::bcj::ia64_decode(&output, *start_offset)
            }
            Filter::Sparc { start_offset } => {
                crate::compress::bcj::sparc_decode(&output, *start_offset)
            }
            Filter::Arm { start_offset } => {
                crate::compress::bcj::arm_decode(&output, *start_offset)
            }
            Filter::ArmThumb { start_offset } => {
                crate::compress::bcj::armthumb_decode(&output, *start_offset)
            }
            Filter::Arm64 { start_offset } => {
                crate::compress::bcj::arm64_decode(&output, *start_offset)
            }
            Filter::RiscV { start_offset } => {
                crate::compress::bcj::riscv_decode(&output, *start_offset)
            }
            Filter::Delta { distance } => {
                crate::compress::delta::decode(&output, *distance as usize)?
            }
            Filter::Unknown { id, properties } => {
                if let Some(codec) = registry.and_then(|registry| registry.get(*id)) {
                    codec.decode(&output, properties)?
                } else {
                    return Err(Error::Unsupported("xz: unsupported custom/unknown filter"));
                }
            }
        };
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::*;

    struct XorCodec;

    impl crate::compress::xz::registry::FilterCodec for XorCodec {
        fn filter_id(&self) -> u64 {
            0x1234
        }

        fn encode(&self, input: &[u8], properties: &[u8]) -> Result<Vec<u8>, Error> {
            let key = properties.first().copied().unwrap_or(0);
            Ok(input.iter().map(|byte| byte ^ key).collect())
        }

        fn decode(&self, input: &[u8], properties: &[u8]) -> Result<Vec<u8>, Error> {
            self.encode(input, properties)
        }
    }

    #[test]
    fn test_apply_decoder_filters_uses_registered_unknown_filter() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let decoded = apply_decoder_filters(
            &[b'a' ^ 0x55, b'b' ^ 0x55],
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
            Some(&registry),
        )
        .unwrap();
        assert_eq!(decoded, b"ab");
    }

    #[test]
    fn test_apply_decoder_filters_rejects_unregistered_unknown_filter() {
        assert!(matches!(
            apply_decoder_filters(
                b"ab",
                &[Filter::Unknown {
                    id: 0x1234,
                    properties: vec![0x55],
                }],
                None,
            ),
            Err(Error::Unsupported("xz: unsupported custom/unknown filter"))
        ));
    }

    #[test]
    fn test_apply_encoder_filters_uses_registered_unknown_filter() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = apply_encoder_filters(
            b"ab",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
            Some(&registry),
        )
        .unwrap();
        assert_eq!(encoded, vec![b'a' ^ 0x55, b'b' ^ 0x55]);
    }

    #[test]
    fn test_apply_encoder_filters_rejects_unregistered_unknown_filter() {
        assert!(matches!(
            apply_encoder_filters(
                b"ab",
                &[Filter::Unknown {
                    id: 0x1234,
                    properties: vec![0x55],
                }],
                None,
            ),
            Err(Error::Unsupported("xz: unsupported custom/unknown filter"))
        ));
    }

    #[test]
    fn test_validate_bcj_alignment_powerpc() {
        // Misaligned
        assert!(matches!(
            Filter::PowerPc { start_offset: 3 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        // Aligned
        assert!(Filter::PowerPc { start_offset: 4 }.validate().is_ok());
        assert!(Filter::PowerPc { start_offset: 0 }.validate().is_ok());
    }

    #[test]
    fn test_validate_bcj_alignment_arm() {
        // Misaligned
        assert!(matches!(
            Filter::Arm { start_offset: 1 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        // Aligned
        assert!(Filter::Arm { start_offset: 8 }.validate().is_ok());
        assert!(Filter::Arm { start_offset: 0 }.validate().is_ok());
    }

    #[test]
    fn test_validate_bcj_alignment_ia64() {
        assert!(matches!(
            Filter::Ia64 { start_offset: 4 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        assert!(Filter::Ia64 { start_offset: 16 }.validate().is_ok());
    }

    #[test]
    fn test_validate_bcj_alignment_armthumb() {
        assert!(matches!(
            Filter::ArmThumb { start_offset: 1 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        assert!(Filter::ArmThumb { start_offset: 2 }.validate().is_ok());
    }

    #[test]
    fn test_validate_bcj_alignment_sparc() {
        assert!(matches!(
            Filter::Sparc { start_offset: 3 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        assert!(Filter::Sparc { start_offset: 4 }.validate().is_ok());
    }

    #[test]
    fn test_validate_bcj_alignment_arm64() {
        assert!(matches!(
            Filter::Arm64 { start_offset: 1 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        assert!(Filter::Arm64 { start_offset: 4 }.validate().is_ok());
    }

    #[test]
    fn test_validate_bcj_alignment_riscv() {
        assert!(matches!(
            Filter::RiscV { start_offset: 1 }.validate(),
            Err(Error::InvalidData(msg)) if msg.contains("not aligned")
        ));
        assert!(Filter::RiscV { start_offset: 2 }.validate().is_ok());
    }

    #[test]
    fn test_validate_unknown_reserved_high_id_rejected() {
        // xz-file-format.txt §3.1.5: Filter IDs >= 2^62 must never appear
        // in a List of Filter Flags, so emitting one is invalid too.
        assert!(matches!(
            Filter::Unknown {
                id: FILTER_ID_RESERVED_START,
                properties: vec![],
            }
            .validate(),
            Err(Error::InvalidData("xz: reserved filter ID (>= 2^62)"))
        ));
        // The largest usable Filter ID remains a valid custom ID.
        assert!(
            Filter::Unknown {
                id: FILTER_ID_RESERVED_START - 1,
                properties: vec![],
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn test_validate_bcj_x86_any_alignment() {
        // x86 has no alignment requirement
        assert!(Filter::X86 { start_offset: 1 }.validate().is_ok());
        assert!(Filter::X86 { start_offset: 3 }.validate().is_ok());
        assert!(Filter::X86 { start_offset: 0 }.validate().is_ok());
    }
}
