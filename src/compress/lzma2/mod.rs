//! LZMA2 codec (chunk-based LZMA compression).
//!
//! The chunk format follows liblzma coder semantics (public domain);
//! xz-file-format.txt covers only the filter properties byte (§5.3.1)
//! and leaves the chunk layout out of scope (§3.2).
//!
//! LZMA2 splits data into independently decompressible chunks,
//! each preceded by a control byte that indicates the reset level
//! and whether the chunk is LZMA-compressed or stored raw.
//!
//! Control byte encoding:
//! - `0x00`: End marker
//! - `0x01`: Uncompressed chunk, dictionary reset
//! - `0x02`: Uncompressed chunk, no dictionary reset
//! - `0x80..=0x9F`: LZMA chunk, no reset
//! - `0xA0..=0xBF`: LZMA chunk, state reset
//! - `0xC0..=0xDF`: LZMA chunk, state + properties reset
//! - `0xE0..=0xFF`: LZMA chunk, all reset (state + properties + dictionary)

use alloc::vec::Vec;

use crate::compress::lzma::{self, LzmaDecoderState, LzmaProperties};
use crate::error::Error;

/// Maximum uncompressed chunk size (2 MiB, 21-bit field).
const MAX_UNCOMPRESSED: usize = 1 << 21; // 2_097_152

/// Maximum compressed chunk size (64 KiB, 16-bit field).
const MAX_COMPRESSED: usize = 1 << 16; // 65_536

/// LZMA properties byte for lc=3, lp=0, pb=2: (pb * 45 + lp) * 9 + lc = 93 = 0x5D.
const PROPS_BYTE: u8 = LzmaProperties::LZIP.to_props_byte();

/// Encode data as an LZMA2 stream.
///
/// Uses LZMA1 compression with full reset per chunk and falls back to
/// uncompressed storage when LZMA cannot reduce size.
pub(crate) fn lzma2_encode(data: &[u8], dict_size: u32) -> Vec<u8> {
    let mut output = Vec::new();
    let mut pos = 0;
    let mut first = true;

    while pos < data.len() {
        let chunk_end = (pos + MAX_UNCOMPRESSED).min(data.len());
        let chunk = &data[pos..chunk_end];
        let uncompressed_size = chunk.len();

        // Try LZMA compression
        let compressed =
            lzma::lzma_encode_with_props_no_eos(chunk, dict_size, LzmaProperties::LZIP);

        if compressed.len() < uncompressed_size && compressed.len() <= MAX_COMPRESSED {
            // LZMA chunk with full reset (0xE0): always reset state, props, and dict
            let control_base = 0xE0u8;
            let u_size = uncompressed_size - 1; // stored as size-1
            let c_size = compressed.len() - 1; // stored as size-1 (does not include props byte)

            // Control byte: bits 4-0 = uncompressed_size bits 20..16
            let control = control_base | ((u_size >> 16) as u8 & 0x1F);
            output.push(control);
            // Uncompressed size bits 15..8, 7..0
            output.push((u_size >> 8) as u8);
            output.push(u_size as u8);
            // Compressed size bits 15..8, 7..0 (big-endian)
            output.push((c_size >> 8) as u8);
            output.push(c_size as u8);
            // Properties byte (for 0xC0+ control)
            output.push(PROPS_BYTE);
            // Compressed LZMA data
            output.extend_from_slice(&compressed);
        } else {
            // Uncompressed chunk
            // Split into 64KB sub-chunks if needed
            let mut sub_pos = 0;
            while sub_pos < chunk.len() {
                let sub_end = (sub_pos + MAX_COMPRESSED).min(chunk.len());
                let sub_chunk = &chunk[sub_pos..sub_end];
                let sub_size = sub_chunk.len() - 1; // stored as size-1

                // 0x01 = uncompressed with dict reset, 0x02 = without
                let control = if first && sub_pos == 0 {
                    0x01u8
                } else {
                    0x02u8
                };
                output.push(control);
                // Size bits 15..8, 7..0 (big-endian)
                output.push((sub_size >> 8) as u8);
                output.push(sub_size as u8);
                output.extend_from_slice(sub_chunk);

                sub_pos = sub_end;
            }
        }

        first = false;
        pos = chunk_end;
    }

    // End marker
    output.push(0x00);
    output
}

/// Decode an LZMA2 stream.
///
/// Returns the decompressed data.
pub(crate) fn lzma2_decode(data: &[u8], dict_size: u32) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut pos = 0;
    let mut current_props = LzmaProperties::LZIP;
    let mut dict_reset_pos = 0usize;
    let mut decoder_state = LzmaDecoderState::new();

    loop {
        if pos >= data.len() {
            return Err(Error::UnexpectedEof);
        }

        let control = data[pos];
        pos += 1;

        if control == 0x00 {
            // End marker
            break;
        }

        if control <= 0x02 {
            // Uncompressed chunk
            if pos + 2 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let size = ((data[pos] as usize) << 8 | data[pos + 1] as usize) + 1;
            pos += 2;

            if pos + size > data.len() {
                return Err(Error::UnexpectedEof);
            }

            if control == 0x01 {
                // Dictionary reset — for streaming decoders this resets the
                // dictionary history visible to following chunks.
                dict_reset_pos = output.len();
            }

            output.extend_from_slice(&data[pos..pos + size]);
            pos += size;
        } else if control >= 0x80 {
            // LZMA chunk
            let reset_level = (control >> 5) & 0x07;
            // reset_level is always >= 0b100 here because control >= 0x80
            // guarantees bit 7 is set, so (control >> 5) & 0x07 >= 4.

            // Parse uncompressed size (21 bits)
            if pos + 4 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let u_size = (((control as usize) & 0x1F) << 16)
                | ((data[pos] as usize) << 8)
                | (data[pos + 1] as usize);
            let u_size = u_size + 1;
            pos += 2;

            // Parse compressed size (16 bits)
            let c_size = ((data[pos] as usize) << 8 | data[pos + 1] as usize) + 1;
            pos += 2;

            // Properties byte present if control >= 0xC0
            let has_props = reset_level >= 0b110;
            if has_props {
                if pos >= data.len() {
                    return Err(Error::UnexpectedEof);
                }
                let props_byte = data[pos];
                pos += 1;
                current_props = LzmaProperties::from_props_byte(props_byte)
                    .map_err(|_| Error::InvalidData("xz: invalid LZMA2 properties"))?;
            }

            if pos + c_size > data.len() {
                return Err(Error::UnexpectedEof);
            }

            let compressed = &data[pos..pos + c_size];
            pos += c_size;

            if reset_level >= 0b101 {
                decoder_state.reset();
            }

            if reset_level == 0b111 {
                dict_reset_pos = output.len();
            }

            let history = &output[dict_reset_pos..];
            let (decoded, _consumed) = lzma::lzma_decode_with_props_and_size_and_history_and_state(
                compressed,
                dict_size,
                current_props,
                u_size,
                history,
                &mut decoder_state,
            )?;

            if decoded.len() != u_size {
                return Err(Error::InvalidData("xz: LZMA2 uncompressed size mismatch"));
            }

            output.extend_from_slice(&decoded);
        } else {
            // Control bytes 0x03..=0x7F are invalid
            return Err(Error::InvalidData("xz: invalid LZMA2 control byte"));
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_lzma2_roundtrip_empty() {
        let data = b"";
        let encoded = lzma2_encode(data, 4096);
        assert_eq!(encoded.last(), Some(&0x00)); // end marker
        let decoded = lzma2_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma2_roundtrip_hello() {
        let data = b"Hello, World!";
        let encoded = lzma2_encode(data, 4096);
        let decoded = lzma2_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma2_roundtrip_repeated() {
        let data = b"The quick brown fox. ".repeat(200);
        let encoded = lzma2_encode(&data, 4096);
        let decoded = lzma2_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma2_roundtrip_all_bytes() {
        let data: alloc::vec::Vec<u8> = (0..=255).collect();
        let encoded = lzma2_encode(&data, 4096);
        let decoded = lzma2_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma2_end_marker_only() {
        // Just the end marker = empty data
        let encoded = [0x00];
        let decoded = lzma2_decode(&encoded, 4096).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_lzma2_invalid_control() {
        // Control byte 0x50 is in the invalid range 0x03..=0x7F
        let encoded = [0x50];
        assert!(lzma2_decode(&encoded, 4096).is_err());
    }

    #[test]
    fn test_lzma2_truncated() {
        // LZMA control byte but no following data
        let encoded = [0xE0];
        assert!(lzma2_decode(&encoded, 4096).is_err());
    }

    #[test]
    fn test_lzma2_control_byte_ranges() {
        let compressed = lzma::lzma_encode(b"A", 4096);
        let c_size = compressed.len() - 1;

        let uncompressed_chunk = [0x02, 0x00, 0x00, b'A', 0x00];
        assert_eq!(lzma2_decode(&uncompressed_chunk, 4096).unwrap(), b"A");

        for &control in &[0x80u8, 0xA0u8] {
            let mut encoded = vec![
                control,
                0x00,
                0x00, // u_size = 1
                ((c_size >> 8) & 0xFF) as u8,
                (c_size & 0xFF) as u8,
            ];
            encoded.extend_from_slice(&compressed);
            encoded.push(0x00);
            assert_eq!(lzma2_decode(&encoded, 4096).unwrap(), b"A");
        }

        let mut encoded = vec![
            0xC0,
            0x00,
            0x00, // u_size = 1
            ((c_size >> 8) & 0xFF) as u8,
            (c_size & 0xFF) as u8,
            PROPS_BYTE,
        ];
        encoded.extend_from_slice(&compressed);
        encoded.push(0x00);
        assert_eq!(lzma2_decode(&encoded, 4096).unwrap(), b"A");
    }

    #[test]
    fn test_lzma2_invalid_control_byte_boundaries() {
        // 0x03 is the first invalid control byte
        assert!(lzma2_decode(&[0x03], 4096).is_err());
        // 0x7F is the last invalid control byte before the LZMA range (0x80+)
        assert!(lzma2_decode(&[0x7F], 4096).is_err());
    }

    #[test]
    fn test_lzma2_roundtrip_minimum_dict_size() {
        // Minimum realistic dict_size (1 byte — the encoder should still work)
        let data = b"test data for tiny dict";
        let encoded = lzma2_encode(data, 1);
        let decoded = lzma2_decode(&encoded, 1).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma2_roundtrip_large_dict_size() {
        // Large dict_size (16 MiB)
        let data = b"test data for large dict";
        let encoded = lzma2_encode(data, 1 << 24);
        let decoded = lzma2_decode(&encoded, 1 << 24).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma2_decode_non_default_props() {
        let props = LzmaProperties {
            lc: 4,
            lp: 0,
            pb: 0,
        };
        let compressed = lzma::lzma_encode_with_props(b"props", 4096, props);
        let c_size = compressed.len() - 1;

        let mut encoded = vec![
            0xC0,
            0x00,
            0x04, // u_size = 5
            ((c_size >> 8) & 0xFF) as u8,
            (c_size & 0xFF) as u8,
            props.to_props_byte(),
        ];
        encoded.extend_from_slice(&compressed);
        encoded.push(0x00);

        assert_eq!(lzma2_decode(&encoded, 4096).unwrap(), b"props");
    }
}
