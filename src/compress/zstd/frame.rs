use crate::error::Error;

/// Zstd magic number (little-endian).
pub(crate) const ZSTD_MAGIC: u32 = 0xFD2FB528;

/// Frame header descriptor.
#[derive(Debug, Clone)]
pub(crate) struct FrameHeader {
    /// Window size in bytes.
    pub(crate) window_size: u64,
    /// Frame content size (if known).
    pub(crate) frame_content_size: Option<u64>,
    /// Whether a checksum is present in the frame.
    pub(crate) has_checksum: bool,
    /// Whether this frame uses a dictionary.
    pub(crate) dictionary_id: Option<u32>,
    /// Single segment flag (used for validation/diagnostics).
    #[allow(dead_code)]
    pub(crate) single_segment: bool,
    /// Total header size (magic + header).
    pub(crate) header_size: usize,
}

impl FrameHeader {
    /// Parse a zstd frame header from the beginning of data.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 5 {
            return Err(Error::UnexpectedEof);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != ZSTD_MAGIC {
            return Err(Error::InvalidData("invalid zstd magic number"));
        }

        let descriptor = data[4];
        let frame_content_size_flag = (descriptor >> 6) & 0x03;
        let single_segment = (descriptor >> 5) & 1 != 0;
        let reserved = (descriptor >> 3) & 1;
        if reserved != 0 {
            return Err(Error::InvalidData(
                "zstd frame descriptor reserved bit is set",
            ));
        }
        let content_checksum_flag = (descriptor >> 2) & 1 != 0;
        let dictionary_id_flag = descriptor & 0x03;

        let mut pos = 5;

        // Window descriptor (absent if single_segment)
        let window_size = if !single_segment {
            if pos >= data.len() {
                return Err(Error::UnexpectedEof);
            }
            let window_desc = data[pos];
            pos += 1;
            let exponent = (window_desc >> 3) as u64;
            let mantissa = (window_desc & 0x07) as u64;
            let window_base = 1u64 << (10 + exponent);
            window_base + (window_base / 8) * mantissa
        } else {
            0 // Will be set to frame_content_size
        };

        // Dictionary ID
        let dict_id_size = match dictionary_id_flag {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => unreachable!(),
        };
        let dictionary_id = if dict_id_size > 0 {
            if pos + dict_id_size > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let id = match dict_id_size {
                1 => data[pos] as u32,
                2 => u16::from_le_bytes([data[pos], data[pos + 1]]) as u32,
                4 => u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]),
                _ => unreachable!(),
            };
            pos += dict_id_size;
            Some(id)
        } else {
            None
        };

        // Frame Content Size
        let fcs_field_size = match frame_content_size_flag {
            0 => {
                if single_segment {
                    1
                } else {
                    0
                }
            }
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };
        let frame_content_size = if fcs_field_size > 0 {
            if pos + fcs_field_size > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let size = match fcs_field_size {
                1 => data[pos] as u64,
                2 => {
                    let v = u16::from_le_bytes([data[pos], data[pos + 1]]) as u64;
                    v + 256 // FCS_Field_Size == 2 means value + 256
                }
                4 => u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as u64,
                8 => u64::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]),
                _ => unreachable!(),
            };
            pos += fcs_field_size;
            Some(size)
        } else {
            None
        };

        let window_size = if single_segment {
            frame_content_size.unwrap_or(0)
        } else {
            window_size
        };

        // RFC 8878 §3.1.1.1.2: reject Window_Size larger than reasonable limits.
        // Use 128 MiB as the practical upper bound (generous compared to the 8 MB
        // conformance level-1 requirement; level-2 decoders may accept more, but
        // 128 MiB is sufficient for all practical workloads).
        const MAX_WINDOW_SIZE: u64 = 128 * 1024 * 1024;
        if window_size > MAX_WINDOW_SIZE {
            return Err(Error::Unsupported(
                "zstd: window size exceeds 128 MiB limit",
            ));
        }

        Ok(FrameHeader {
            window_size,
            frame_content_size,
            has_checksum: content_checksum_flag,
            dictionary_id,
            single_segment,
            header_size: pos,
        })
    }
}

/// Block header (3 bytes).
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockHeader {
    /// Whether this is the last block in the frame.
    pub(crate) last_block: bool,
    /// Block type (0=Raw, 1=RLE, 2=Compressed, 3=Reserved).
    pub(crate) block_type: BlockType,
    /// Block size in bytes.
    pub(crate) block_size: u32,
}

/// Type of a zstd block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockType {
    Raw,
    Rle,
    Compressed,
    Reserved,
}

impl BlockHeader {
    /// Parse a 3-byte block header from the beginning of data.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 3 {
            return Err(Error::UnexpectedEof);
        }
        let val = u32::from_le_bytes([data[0], data[1], data[2], 0]);
        let last_block = val & 1 != 0;
        let block_type = match (val >> 1) & 0x03 {
            0 => BlockType::Raw,
            1 => BlockType::Rle,
            2 => BlockType::Compressed,
            _ => BlockType::Reserved,
        };
        let block_size = val >> 3;

        Ok(BlockHeader {
            last_block,
            block_type,
            block_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_parse() {
        // last_block=1, type=0 (Raw), size=5
        // val = (5 << 3) | (0 << 1) | 1 = 41 = 0x29
        let data = [0x29, 0x00, 0x00];
        let bh = BlockHeader::parse(&data).unwrap();
        assert!(bh.last_block);
        assert_eq!(bh.block_type, BlockType::Raw);
        assert_eq!(bh.block_size, 5);
    }

    // Phase 1: Error detection

    #[test]
    fn test_invalid_zstd_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x00];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_zstd_frame_too_short() {
        // Only magic bytes, no descriptor
        let data = [0x28, 0xB5, 0x2F, 0xFD];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_block_type_reserved_error() {
        // block_type=3 (Reserved): val = (0 << 3) | (3 << 1) | 1 = 7
        let data = [0x07, 0x00, 0x00];
        let bh = BlockHeader::parse(&data).unwrap();
        assert_eq!(bh.block_type, BlockType::Reserved);
    }

    #[test]
    fn test_descriptor_reserved_bit() {
        // Descriptor with reserved bit (bit 3) set → error
        let data = [
            0x28,
            0xB5,
            0x2F,
            0xFD,        // magic
            0b0000_1000, // reserved bit 3 = 1
            0x00,        // window descriptor
        ];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    // Phase 3: Frame header flag combinations

    #[test]
    fn test_fcs_flag_combinations() {
        // Test all FCS_Flag values (0-3) with single_segment=true
        // FCS_Flag=0, single_segment=1: FCS field = 1 byte
        let data0 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,        // magic
            0b0010_0000, // descriptor: FCS=0, SS=1, reserved=0, checksum=0, dict=0
            42,          // FCS = 42 (1 byte)
        ];
        let h = FrameHeader::parse(&data0).unwrap();
        assert_eq!(h.frame_content_size, Some(42));
        assert!(h.single_segment);

        // FCS_Flag=1, single_segment=1: FCS field = 2 bytes (+256)
        let data1 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0110_0000, // FCS=1, SS=1
            0x00,
            0x01, // FCS = 256 + 256 = 512? No: value = u16::from_le_bytes + 256
        ];
        let h = FrameHeader::parse(&data1).unwrap();
        assert_eq!(h.frame_content_size, Some(256 + 256)); // 0x0100 + 256

        // FCS_Flag=2, single_segment=1: FCS field = 4 bytes
        let data2 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b1010_0000, // FCS=2, SS=1
            0x01,
            0x00,
            0x00,
            0x00, // FCS = 1
        ];
        let h = FrameHeader::parse(&data2).unwrap();
        assert_eq!(h.frame_content_size, Some(1));

        // FCS_Flag=3, single_segment=1: FCS field = 8 bytes.
        // Use a small value well within the 128 MiB window-size limit so the parse succeeds.
        let data3 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b1110_0000, // FCS=3, SS=1
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00, // FCS = 1
        ];
        let h = FrameHeader::parse(&data3).unwrap();
        assert_eq!(h.frame_content_size, Some(1));
    }

    #[test]
    fn test_window_size_min() {
        // Window_Descriptor=0x00: exponent=0, mantissa=0 → window_base=1<<10=1024, +0 = 1024
        let data = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0000_0000, // FCS=0, SS=0, checksum=0, dict=0
            0x00,        // window descriptor = 0
        ];
        let h = FrameHeader::parse(&data).unwrap();
        assert_eq!(h.window_size, 1024);
    }

    #[test]
    fn test_window_size_max_descriptor_rejected() {
        // Window_Descriptor=0xFF: exponent=31, mantissa=7
        // window_base = 1<<41 → window_size ≈ 3.75 TiB, far exceeds 128 MiB limit.
        // RFC 8878 §3.1.1.1.2: decoder MUST reject overly large window sizes.
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0b0000_0000, 0xFF];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_window_size_at_limit_accepted() {
        // Window_Descriptor=0x88: exponent=17, mantissa=0 → window_base=1<<27=128MiB, mantissa*0=0
        // window_size = 128 MiB exactly (= MAX_WINDOW_SIZE), must be accepted.
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0b0000_0000, 0x88];
        let h = FrameHeader::parse(&data).unwrap();
        assert_eq!(h.window_size, 128 * 1024 * 1024);
    }

    #[test]
    fn test_window_size_exceeds_limit_rejected() {
        // Window_Descriptor=0x89: exponent=17, mantissa=1 → window_size=144 MiB > 128 MiB.
        // RFC 8878 §3.1.1.1.2: must be rejected as Unsupported.
        let data = [0x28, 0xB5, 0x2F, 0xFD, 0b0000_0000, 0x89];
        let result = FrameHeader::parse(&data);
        assert!(matches!(result, Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_dictionary_id_sizes() {
        // dict_id_flag=1: 1 byte dict ID
        let data1 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0010_0001, // SS=1, dict_id_flag=1
            0x42,        // dict_id = 0x42
            0x00,        // FCS (1 byte, since FCS_flag=0, SS=1)
        ];
        let h = FrameHeader::parse(&data1).unwrap();
        assert_eq!(h.dictionary_id, Some(0x42));

        // dict_id_flag=2: 2 byte dict ID
        let data2 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0010_0010, // SS=1, dict_id_flag=2
            0x34,
            0x12, // dict_id = 0x1234
            0x00, // FCS
        ];
        let h = FrameHeader::parse(&data2).unwrap();
        assert_eq!(h.dictionary_id, Some(0x1234));

        // dict_id_flag=3: 4 byte dict ID
        let data3 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0010_0011, // SS=1, dict_id_flag=3
            0x78,
            0x56,
            0x34,
            0x12, // dict_id = 0x12345678
            0x00, // FCS
        ];
        let h = FrameHeader::parse(&data3).unwrap();
        assert_eq!(h.dictionary_id, Some(0x12345678));
    }

    #[test]
    fn test_checksum_flag() {
        // Checksum bit is bit 2 of descriptor
        let data = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0010_0100, // SS=1, checksum=1
            0x00,        // FCS
        ];
        let h = FrameHeader::parse(&data).unwrap();
        assert!(h.has_checksum);

        let data2 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0010_0000, // SS=1, checksum=0
            0x00,        // FCS
        ];
        let h2 = FrameHeader::parse(&data2).unwrap();
        assert!(!h2.has_checksum);
    }

    #[test]
    fn test_single_segment_false_with_window() {
        // single_segment=0 requires Window_Descriptor byte
        let data = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0000_0000, // SS=0, FCS_flag=0 → no FCS (since SS=0 means FCS_flag=0 → 0 bytes)
            0x00,        // Window_Descriptor: exponent=0, mantissa=0 → 1024
        ];
        let h = FrameHeader::parse(&data).unwrap();
        assert!(!h.single_segment);
        assert_eq!(h.window_size, 1024);
        assert_eq!(h.frame_content_size, None);
    }

    #[test]
    fn test_block_header_max_size() {
        // Block size is 21 bits (max 2^21 - 1 = 2097151)
        let bh_val: u32 = (2097151 << 3) | 0b001; // last=1, type=Raw
        let data = [bh_val as u8, (bh_val >> 8) as u8, (bh_val >> 16) as u8];
        let bh = BlockHeader::parse(&data).unwrap();
        assert_eq!(bh.block_size, 2097151);
        assert!(bh.last_block);
        assert!(matches!(bh.block_type, BlockType::Raw));
    }

    #[test]
    fn test_block_header_min_size() {
        // Block size 0 with RLE type
        let bh_val: u32 = 0b010; // last=0, type=RLE
        let data = [bh_val as u8, (bh_val >> 8) as u8, (bh_val >> 16) as u8];
        let bh = BlockHeader::parse(&data).unwrap();
        assert_eq!(bh.block_size, 0);
        assert!(!bh.last_block);
        assert!(matches!(bh.block_type, BlockType::Rle));
    }

    #[test]
    fn test_fcs_flag1_boundary_values() {
        // FCS_flag=1, single_segment=1 → 2-byte FCS, value = raw + 256
        let data = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0110_0000, // FCS_flag=1, SS=1
            0x00,
            0x00, // FCS = 0 → actual size = 256
        ];
        let h = FrameHeader::parse(&data).unwrap();
        assert_eq!(h.frame_content_size, Some(256));

        let data2 = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b0110_0000,
            0xFF,
            0xFF, // FCS = 65535 → actual size = 65791
        ];
        let h2 = FrameHeader::parse(&data2).unwrap();
        assert_eq!(h2.frame_content_size, Some(65791));
    }

    #[test]
    fn test_fcs_field_truncated() {
        // FCS_flag=3 (8-byte FCS) but data too short
        let data = [
            0x28,
            0xB5,
            0x2F,
            0xFD,
            0b1110_0000, // FCS_flag=3, SS=1
            0x00,
            0x00, // Only 2 bytes of FCS (need 8)
        ];
        let result = FrameHeader::parse(&data);
        assert!(result.is_err());
    }
}
