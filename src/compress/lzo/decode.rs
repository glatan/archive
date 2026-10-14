//! LZO1X decompression with lzop file format parser.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lzo::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::adler32::adler32;
use crate::util::crc32::crc32;

// lzop constants

/// lzop file magic number.
const LZOP_MAGIC: &[u8] = &[0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A];

/// Flag: Adler-32 of uncompressed data present.
const F_ADLER32_D: u32 = 0x0001;
/// Flag: CRC-32 of uncompressed data present.
const F_CRC32_D: u32 = 0x0100;
/// Flag: Adler-32 of compressed data present.
const F_ADLER32_C: u32 = 0x0002;
/// Flag: CRC-32 of compressed data present.
const F_CRC32_C: u32 = 0x0200;
/// Flag: extra field present in header.
const F_H_EXTRA: u32 = 0x0040;
/// Flag: filter present in header.
const F_H_FILTER: u32 = 0x0800;
/// Flag: header checksum is CRC-32 instead of Adler-32 (lzop --crc32).
const F_H_CRC32: u32 = 0x1000;
/// Flag: archive contains multiple members (lzop -o / multiple files).
const F_MULTIPART: u32 = 0x0400;

/// Decode lzop format data.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if the magic number is wrong, header is malformed,
/// or compressed data is corrupt.
///
/// # Examples
///
/// ```
/// use archive::compress::lzo::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() < LZOP_MAGIC.len() + 2 {
        return Err(Error::InvalidData("lzo: input too short"));
    }

    let mut pos = 0;
    let mut output = Vec::new();
    let mut members = 0usize;

    loop {
        if pos + LZOP_MAGIC.len() > input.len() {
            if members == 0 {
                return Err(Error::InvalidData("lzo: input too short"));
            }
            break; // trailing data after the last member
        }

        // Magic number
        if &input[pos..pos + LZOP_MAGIC.len()] != LZOP_MAGIC {
            if members == 0 {
                return Err(Error::InvalidData("lzo: invalid magic number"));
            }
            break; // trailing data after the last member
        }
        pos += LZOP_MAGIC.len();

        let header_start = pos;

        // Version
        let version = read_u16_be(input, &mut pos)?;
        let _lib_version = read_u16_be(input, &mut pos)?;

        // version_needed and level fields only exist in version >= 0x0940
        if version < 0x0940 {
            return Err(Error::Unsupported(
                "lzo: lzop version < 0x0940 not supported",
            ));
        }

        let version_needed = read_u16_be(input, &mut pos)?;
        if version_needed > 0x1040 {
            return Err(Error::Unsupported("lzo: version too new"));
        }

        // Method and level
        let method = read_byte(input, &mut pos)?;
        if method != 1 && method != 2 && method != 3 {
            return Err(Error::Unsupported("lzo: unsupported compression method"));
        }
        let _level = read_byte(input, &mut pos)?;

        // Flags
        let flags = read_u32_be(input, &mut pos)?;

        // Filter (only if flag set)
        if flags & F_H_FILTER != 0 {
            let _filter = read_u32_be(input, &mut pos)?;
        }

        // Extra field (only if flag set)
        if flags & F_H_EXTRA != 0 {
            let extra_len = read_u32_be(input, &mut pos)? as usize;
            if pos + extra_len > input.len() {
                return Err(Error::UnexpectedEof);
            }
            pos += extra_len;
        }

        // Mode, mtime
        let _mode = read_u32_be(input, &mut pos)?;
        let _mtime_low = read_u32_be(input, &mut pos)?;

        // mtime_high present in version >= 0x0940
        let _mtime_high = read_u32_be(input, &mut pos)?;

        // Filename
        let name_len = read_byte(input, &mut pos)? as usize;
        if name_len > 0 {
            if pos + name_len > input.len() {
                return Err(Error::UnexpectedEof);
            }
            pos += name_len;
        }

        // Header checksum: CRC-32 when F_H_CRC32 is set (lzop --crc32),
        // Adler-32 otherwise.
        let header_data = &input[header_start..pos];
        let expected_hc = if flags & F_H_CRC32 != 0 {
            crc32(header_data)
        } else {
            adler32(header_data)
        };
        let actual_hc = read_u32_be(input, &mut pos)?;
        if actual_hc != expected_hc {
            return Err(Error::InvalidData("lzo: header checksum mismatch"));
        }

        let has_adler32_d = (flags & F_ADLER32_D) != 0;
        let has_crc32_d = (flags & F_CRC32_D) != 0;
        let has_adler32_c = (flags & F_ADLER32_C) != 0;
        let has_crc32_c = (flags & F_CRC32_C) != 0;

        // Read blocks
        loop {
            let uncompressed_len = read_u32_be(input, &mut pos)? as usize;

            if uncompressed_len == 0 {
                break; // End mark
            }

            let compressed_len = read_u32_be(input, &mut pos)? as usize;

            let is_compressed = compressed_len < uncompressed_len;

            // Uncompressed data checksums (always present if flag set)
            let expected_adler_d = if has_adler32_d {
                Some(read_u32_be(input, &mut pos)?)
            } else {
                None
            };

            let expected_crc32_d = if has_crc32_d {
                Some(read_u32_be(input, &mut pos)?)
            } else {
                None
            };

            // Compressed data checksums (only present when block is actually compressed)
            let expected_adler32_c = if is_compressed && has_adler32_c {
                Some(read_u32_be(input, &mut pos)?)
            } else {
                None
            };

            let expected_crc32_c = if is_compressed && has_crc32_c {
                Some(read_u32_be(input, &mut pos)?)
            } else {
                None
            };

            // Block data
            if pos + compressed_len > input.len() {
                return Err(Error::UnexpectedEof);
            }
            let block_data = &input[pos..pos + compressed_len];
            pos += compressed_len;

            // Verify CRC-32 of compressed data
            if let Some(expected) = expected_crc32_c {
                let actual = crc32(block_data);
                if actual != expected {
                    return Err(Error::ChecksumMismatch { expected, actual });
                }
            }

            // Verify Adler-32 of compressed data
            if let Some(expected) = expected_adler32_c {
                let actual = adler32(block_data);
                if actual != expected {
                    return Err(Error::ChecksumMismatch { expected, actual });
                }
            }

            if compressed_len > uncompressed_len {
                return Err(Error::InvalidData(
                    "lzo: compressed block larger than uncompressed",
                ));
            }
            if compressed_len == uncompressed_len {
                // Stored uncompressed
                output.extend_from_slice(block_data);
            } else {
                // Decompress LZO1X block
                let decompressed = decompress_lzo1x(block_data, uncompressed_len)?;
                if decompressed.len() != uncompressed_len {
                    return Err(Error::InvalidData("lzo: decompressed size mismatch"));
                }
                output.extend_from_slice(&decompressed);
            }

            // Verify Adler-32 of uncompressed data
            if let Some(expected) = expected_adler_d {
                let actual = adler32(&output[output.len() - uncompressed_len..]);
                if actual != expected {
                    return Err(Error::ChecksumMismatch { expected, actual });
                }
            }

            // Verify CRC-32 of uncompressed data
            if let Some(expected) = expected_crc32_d {
                let actual = crc32(&output[output.len() - uncompressed_len..]);
                if actual != expected {
                    return Err(Error::ChecksumMismatch { expected, actual });
                }
            }
        }

        let _ = flags & F_MULTIPART; // members are self-terminating; the flag
        // is informational for the decoder
        members += 1;
    }

    Ok(output)
}

/// Decompress a single LZO1X block using standard bytecode.
///
/// Match types by first instruction byte:
/// - M1: 0x00..0x0F (state 1-3): short match, offset 1..=1024, len 2
/// - M1: 0x00..0x0F (state >= 4): long-offset match, offset 2049..=3072, len 3
/// - M2: 0x40..0xFF: 2-byte match, offset 1..=2048, len 3..=8
/// - M3: 0x20..0x3F: 3-byte match, offset 1..=16384, len 3+
/// - M4: 0x10..0x1F: 3-byte match, offset 16385..=49151, len 3+ (or end marker)
/// - Literal run: 0x00..0x0F (state == 0): literal copy
/// - v1 only: M4 with distance 0xbfff encodes a run of zeros (LZO-RLE)
///
/// The LE16 offset bytes encode S (trailing literal count) in the low 2 bits.
/// M3: `((offset - 1) << 2) | S`, M4: `(base << 2) | S` where base is
/// the reduced offset within the M4 range.
pub(crate) fn decompress_lzo1x(src: &[u8], expected_len: usize) -> Result<Vec<u8>, Error> {
    let mut dst = Vec::with_capacity(expected_len);
    let mut sp = 0usize;
    #[allow(unused_assignments)]
    let mut state: usize = 0;
    let mut rle = false;

    if sp >= src.len() {
        return Ok(dst);
    }

    // First byte 17 marks a versioned bitstream when the stream is at least
    // 5 bytes long (the shortest possible versioned bitstream): the second
    // byte is the bitstream version (kernel lzo.rst, "Byte sequences").
    // Version 1 (LZO-RLE) adds a zero-run encoding to the M4 instruction.
    // A leading 17 in a shorter stream is a regular M4 instruction byte in
    // version 0, not a version header.
    if src[sp] == 17 && src.len() >= 5 {
        let version = src[sp + 1];
        if version > 1 {
            return Err(Error::Unsupported("lzo: unsupported bitstream version"));
        }
        rle = version == 1;
        sp += 2;
    }

    let t = src[sp] as usize;

    // Initial literal run
    if t > 17 {
        // First byte > 17: (t - 17) literal bytes follow
        let lit_len = t - 17;
        sp += 1;
        copy_literals(src, &mut sp, &mut dst, lit_len)?;
        state = if lit_len < 4 { lit_len } else { 4 };
    } else if t < 16 {
        // First byte < 16 (state=0): literal run
        // byte 1-15: count = byte + 3 (4-18 literals)
        // byte 0: extended count = 18 + VLE
        let lit_len = if t == 0 {
            sp += 1;
            18 + read_vle(src, &mut sp)?
        } else {
            sp += 1;
            t + 3
        };
        copy_literals(src, &mut sp, &mut dst, lit_len)?;
        state = 4;
    } else {
        // t >= 16: match instruction, handle in main loop
        state = 0;
    }

    // Main decode loop
    loop {
        if sp >= src.len() {
            break;
        }

        let inst = src[sp] as usize;
        sp += 1;

        if inst >= 64 {
            // M2 match: LLLDDDSS + H
            // length = ((inst >> 5) & 7) + 1 => range 3..8
            // S = inst & 3 (trailing literal count)
            // offset = (H << 3) + ((inst >> 2) & 7) + 1
            let match_len = ((inst >> 5) & 7) + 1;
            let s = inst & 3;
            let ddd = (inst >> 2) & 7;
            let h = src.get(sp).copied().ok_or(Error::UnexpectedEof)? as usize;
            sp += 1;
            let offset = (h << 3) + ddd + 1;

            copy_match(&mut dst, offset, match_len)?;

            if s > 0 {
                copy_literals(src, &mut sp, &mut dst, s)?;
            }
            state = s;
        } else if inst >= 32 {
            // M3 match: 001LLLLL + LE16((offset-1)<<2 | S)
            // if LLLLL == 0: extended length = 31 + VLE, then +2
            // else: length = LLLLL + 2
            let mut match_len = inst & 0x1F;
            if match_len == 0 {
                match_len = 31 + read_vle(src, &mut sp)?;
            }
            match_len += 2;

            if sp + 2 > src.len() {
                return Err(Error::UnexpectedEof);
            }
            let le16 = (src[sp] as usize) | ((src[sp + 1] as usize) << 8);
            sp += 2;
            let s = le16 & 3;
            let offset = (le16 >> 2) + 1;

            copy_match(&mut dst, offset, match_len)?;

            if s > 0 {
                copy_literals(src, &mut sp, &mut dst, s)?;
            }
            state = s;
        } else if inst >= 16 {
            // M4 match: 0001HLLL + LE16(base<<2 | S)
            // H = (inst >> 3) & 1
            // if LLL == 0: extended length = 7 + VLE, then +2
            // else: length = LLL + 2
            // offset = 16384 + (H << 14) + base
            // End-of-stream when offset == 16384 and length == 3
            //
            // Version 1 only (LZO-RLE): H = 1 with the LE16 D bits all set
            // (distance 0xbfff) encodes a run of zeros followed by a fourth
            // byte X: run length = ((X << 3) | LLL) + 4. The run form is
            // detected on the raw LE16 before the VLE parse, so a zero run
            // never carries a VLE length even when LLL == 0 (kernel lzo.rst).
            if rle && (inst & 0x08) != 0 && sp + 2 <= src.len() {
                let le16 = (src[sp] as usize) | ((src[sp + 1] as usize) << 8);
                if le16 >> 2 == 0x3FFF {
                    sp += 2;
                    let s = le16 & 3;
                    let x = src.get(sp).copied().ok_or(Error::UnexpectedEof)? as usize;
                    sp += 1;
                    let run_len = ((x << 3) | (inst & 0x07)) + 4;
                    dst.resize(dst.len() + run_len, 0);
                    if s > 0 {
                        copy_literals(src, &mut sp, &mut dst, s)?;
                    }
                    state = s;
                    continue;
                }
            }
            let mut match_len = inst & 0x07;
            if match_len == 0 {
                match_len = 7 + read_vle(src, &mut sp)?;
            }
            match_len += 2;

            if sp + 2 > src.len() {
                return Err(Error::UnexpectedEof);
            }
            let le16 = (src[sp] as usize) | ((src[sp + 1] as usize) << 8);
            sp += 2;
            let s = le16 & 3;
            let base = le16 >> 2;
            let h = (inst >> 3) & 1;
            let offset = 16384 + (h << 14) + base;

            // End-of-stream marker: offset == 16384 (kernel lzo.rst treats
            // distance 16384 as EOS regardless of the length field).
            if offset == 16384 {
                break;
            }

            copy_match(&mut dst, offset, match_len)?;

            if s > 0 {
                copy_literals(src, &mut sp, &mut dst, s)?;
            }
            state = s;
        } else {
            // inst < 16
            if state == 0 {
                // State 0: literal run
                // byte 1-15: count = byte + 3
                // byte 0: extended count = 18 + VLE
                let lit_len = if inst == 0 {
                    18 + read_vle(src, &mut sp)?
                } else {
                    inst + 3
                };
                copy_literals(src, &mut sp, &mut dst, lit_len)?;
                state = 4;
            } else if state >= 4 {
                // State 4: M1 long-offset short match
                // 0000DDSS + H
                // offset = (H << 2) + DD + 2049, where DD = (inst >> 2) & 3
                // length = 3
                // S = inst & 3 (trailing literals)
                let s = inst & 3;
                let dd = (inst >> 2) & 3;
                let h = src.get(sp).copied().ok_or(Error::UnexpectedEof)? as usize;
                sp += 1;
                let offset = (h << 2) + dd + 2049;

                copy_match(&mut dst, offset, 3)?;

                if s > 0 {
                    copy_literals(src, &mut sp, &mut dst, s)?;
                }
                state = s;
            } else {
                // State 1-3: M1 short match
                // 0000PPSS + H
                // offset = (H << 2) + PP + 1, where PP = (inst >> 2) & 3
                // length = 2
                // S = inst & 3 (trailing literals)
                let s = inst & 3;
                let pp = (inst >> 2) & 3;
                let h = src.get(sp).copied().ok_or(Error::UnexpectedEof)? as usize;
                sp += 1;
                let offset = (h << 2) + pp + 1;

                copy_match(&mut dst, offset, 2)?;

                if s > 0 {
                    copy_literals(src, &mut sp, &mut dst, s)?;
                }
                state = s;
            }
        }
    }

    Ok(dst)
}

/// Read VLE: count zero bytes * 255 + next non-zero byte.
fn read_vle(src: &[u8], sp: &mut usize) -> Result<usize, Error> {
    let mut value = 0usize;
    while *sp < src.len() && src[*sp] == 0 {
        value += 255;
        *sp += 1;
    }
    if *sp >= src.len() {
        return Err(Error::UnexpectedEof);
    }
    value += src[*sp] as usize;
    *sp += 1;
    Ok(value)
}

fn copy_literals(src: &[u8], sp: &mut usize, dst: &mut Vec<u8>, count: usize) -> Result<(), Error> {
    if *sp + count > src.len() {
        return Err(Error::UnexpectedEof);
    }
    dst.extend_from_slice(&src[*sp..*sp + count]);
    *sp += count;
    Ok(())
}

fn copy_match(dst: &mut Vec<u8>, offset: usize, length: usize) -> Result<(), Error> {
    if offset == 0 || offset > dst.len() {
        return Err(Error::InvalidData("lzo: match offset out of range"));
    }
    let start = dst.len() - offset;
    for i in 0..length {
        let b = dst[start + i];
        dst.push(b);
    }
    Ok(())
}

fn read_byte(data: &[u8], pos: &mut usize) -> Result<u8, Error> {
    if *pos >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let b = data[*pos];
    *pos += 1;
    Ok(b)
}

fn read_u16_be(data: &[u8], pos: &mut usize) -> Result<u16, Error> {
    if *pos + 2 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u32_be(data: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

/// Decode lzop format data from a reader.
///
/// # Errors
///
/// Returns an error if reading fails or the data is not valid lzop format.
///
/// # Examples
///
/// ```
/// use archive::compress::lzo::{decode, encode};
///
/// let data = b"Hello, reader!";
/// let compressed = encode::encode(data);
/// let decoded = decode::decode_reader(&compressed[..]).unwrap();
/// assert_eq!(decoded, data);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    decode(&buf).map_err(Into::into)
}

/// Decode lzop format data with a maximum output size limit.
///
/// Returns `Error::OutputLimitExceeded` if the decompressed output
/// would exceed `max_output` bytes.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let result = decode(input)?;
    if result.len() > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn rebuild_header_with_options(
        original: &[u8],
        version_needed: Option<u16>,
        method: Option<u8>,
        add_flags: u32,
        filter: Option<u32>,
        extra: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut patched = Vec::new();
        patched.extend_from_slice(LZOP_MAGIC);
        patched.extend_from_slice(&original[9..11]); // version
        patched.extend_from_slice(&original[11..13]); // lib_version
        patched.extend_from_slice(
            &version_needed
                .unwrap_or(u16::from_be_bytes([original[13], original[14]]))
                .to_be_bytes(),
        );
        patched.push(method.unwrap_or(original[15]));
        patched.push(original[16]); // level

        let old_flags =
            u32::from_be_bytes([original[17], original[18], original[19], original[20]]);
        let new_flags = old_flags | add_flags;
        patched.extend_from_slice(&new_flags.to_be_bytes());

        if new_flags & F_H_FILTER != 0 {
            patched.extend_from_slice(&filter.unwrap_or(0).to_be_bytes());
        }
        if new_flags & F_H_EXTRA != 0 {
            let extra = extra.unwrap_or(&[]);
            patched.extend_from_slice(&(extra.len() as u32).to_be_bytes());
            patched.extend_from_slice(extra);
        }

        patched.extend_from_slice(&original[21..34]); // mode, mtimes, filename length
        let hc = adler32(&patched[LZOP_MAGIC.len()..]);
        patched.extend_from_slice(&hc.to_be_bytes());
        patched.extend_from_slice(&original[38..]); // existing block section
        patched
    }

    #[test]
    fn test_invalid_magic() {
        let result = decode(&[0x00; 20]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("magic")));
    }

    #[test]
    fn test_input_too_short() {
        let result = decode(&[0x89, 0x4C, 0x5A]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("too short")));
    }

    #[test]
    fn test_roundtrip_hello() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_v1_bitstream_short_stream_is_v0() {
        // A leading byte 17 in a stream shorter than 5 bytes is not a
        // version header: the stream stays v0 and 17 is a regular M4
        // instruction byte (kernel lzo.rst, "Byte sequences"). Here it is
        // the canonical end-of-stream marker (H=0, LLL=1, distance 0).
        assert!(decompress_lzo1x(&[17, 0, 0], 0).unwrap().is_empty());
    }

    #[test]
    fn test_v1_bitstream_version_byte() {
        // First byte 17 in a stream of at least 5 bytes is a version
        // header: the second byte gives the bitstream version (kernel
        // lzo.rst, "Byte sequences"). A v1 stream without zero runs decodes
        // with v0 instruction semantics.
        let src = [17, 1, 20, b'a', b'b', b'c', 0x11, 0x00, 0x00];
        assert_eq!(decompress_lzo1x(&src, 3).unwrap(), b"abc");

        // Version byte 0 selects v0 instruction semantics after the header.
        let src = [17, 0, 20, b'a', b'b', b'c', 0x11, 0x00, 0x00];
        assert_eq!(decompress_lzo1x(&src, 3).unwrap(), b"abc");

        // Unknown bitstream versions are rejected.
        let src = [17, 2, 20, b'a', b'b', b'c', 0x11, 0x00, 0x00];
        assert!(matches!(
            decompress_lzo1x(&src, 3),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn test_v1_zero_run_decode() {
        // v1 zero run: an M4 instruction with H=1 and the LE16 D bits all
        // set (distance 0xbfff) is followed by a fourth byte X and encodes a
        // run of zeros, run length = ((X << 3) | LLL) + 4 (kernel lzo.rst).
        // Here: 2 literals, then LLL=6, X=0, S=0 gives a run of 10 zeros.
        let src = [
            17, 1, 19, b'a', b'b', 0x1E, 0xFC, 0xFF, 0x00, 0x11, 0x00, 0x00,
        ];
        let mut expected = b"ab".to_vec();
        expected.resize(12, 0);
        assert_eq!(decompress_lzo1x(&src, 12).unwrap(), expected);

        // LLL == 0 zero runs take their length from X alone and do not
        // carry a VLE length field: run length = (2 << 3) + 4 = 20 zeros.
        let src = [
            17, 1, 19, b'a', b'b', 0x18, 0xFC, 0xFF, 0x02, 0x11, 0x00, 0x00,
        ];
        let mut expected = b"ab".to_vec();
        expected.resize(22, 0);
        assert_eq!(decompress_lzo1x(&src, 22).unwrap(), expected);

        // S literals still trail a zero run.
        let src = [
            17, 1, 19, b'a', b'b', 0x1E, 0xFE, 0xFF, 0x00, b'c', b'd', 0x11, 0x00, 0x00,
        ];
        let mut expected = b"ab".to_vec();
        expected.resize(12, 0);
        expected.extend_from_slice(b"cd");
        assert_eq!(decompress_lzo1x(&src, 14).unwrap(), expected);

        // A zero run missing its fourth byte is rejected.
        let src = [17, 1, 19, b'a', b'b', 0x1E, 0xFC, 0xFF];
        assert!(matches!(
            decompress_lzo1x(&src, 12),
            Err(Error::UnexpectedEof)
        ));
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let data = b"A";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let data: alloc::vec::Vec<u8> = (0..=255).collect();
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_large() {
        let data = alloc::vec![0xABu8; 100_000];
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_english_text() {
        let data = b"The quick brown fox jumps over the lazy dog. \
                     The quick brown fox jumps over the lazy dog.";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_header_checksum_mismatch() {
        let mut compressed = super::super::encode::encode(b"test data");
        // Header checksum is the last 4 bytes before block data.
        // Corrupt a byte in the header region (after magic, before checksum).
        // Byte 9 is start of version field.
        compressed[9] ^= 0xFF;
        assert!(
            matches!(decode(&compressed), Err(Error::InvalidData(msg)) if msg.contains("checksum"))
        );
    }

    #[test]
    fn test_block_adler32_mismatch() {
        let data = b"Hello, World!";
        let mut compressed = super::super::encode::encode(data);
        // Corrupt data in the block payload (last bytes before end mark).
        // End mark is last 4 bytes. Block data is just before that.
        let end_mark = compressed.len() - 4;
        if end_mark > 1 {
            compressed[end_mark - 1] ^= 0xFF;
        }
        assert!(decode(&compressed).is_err());
    }

    #[test]
    fn test_roundtrip_multi_block() {
        // >256KB to force multiple lzop blocks
        let data = alloc::vec![0x42u8; 300_000];
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_match_offset_out_of_range() {
        // M1 state 1-3 with large offset on very short output
        // First emit 1 literal via first-byte > 17 path, then M1 with offset > 1
        let block2 = &[
            18u8, // 18 > 17 → 1 literal follows
            b'X', // literal
            // state = 1 (< 4), next inst < 16 → M1 state 1-3
            // 0000PPSS + H, offset = (H<<2) + PP + 1, len=2
            // inst=0b0000_1100 = 0x0C, PP=3, S=0, H=0xFF → offset = (255<<2)+3+1 = 1024
            // But we only have 1 byte of output → offset 1024 is invalid
            0x0C, 0xFF,
        ];
        assert!(decompress_lzo1x(block2, 100).is_err());
    }

    #[test]
    fn test_initial_literal_run_byte_gt_17() {
        let src = [20, b'x', b'y', b'z', 0x11, 0x00, 0x00];
        let decoded = decompress_lzo1x(&src, 3).unwrap();
        assert_eq!(decoded, b"xyz");
    }

    #[test]
    fn test_m1_short_match_state_1_to_3() {
        // First byte 20 => 3 initial literals, so state becomes 3.
        // Then inst 0x08 => M1 short match with PP=2, S=0 and H=0 => offset=3, len=2.
        let src = [20, b'a', b'b', b'c', 0x08, 0x00, 0x11, 0x00, 0x00];
        let decoded = decompress_lzo1x(&src, 5).unwrap();
        assert_eq!(decoded, b"abcab");
    }

    #[test]
    fn test_decompress_empty_block() {
        let result = decompress_lzo1x(&[], 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_roundtrip_long_match() {
        // Create data with a long repeated pattern to exercise M3 extended VLE encoding
        // Pattern: 40 unique bytes repeated many times → matches > 33 bytes
        let mut data = Vec::new();
        let pattern: Vec<u8> = (0..40).collect();
        for _ in 0..200 {
            data.extend_from_slice(&pattern);
        }
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_truncated_block_data() {
        let compressed = super::super::encode::encode(b"test data here");
        // Truncate the compressed data in the middle of a block
        let truncated = &compressed[..compressed.len() - 2];
        assert!(decode(truncated).is_err());
    }

    #[test]
    fn test_roundtrip_long_distance() {
        // Create data that requires M4 encoding (offset > 16384).
        // A unique 20KB prefix, then repeat the first 4 bytes at offset > 16384.
        let mut data = Vec::new();
        // 20000 bytes of pseudo-random data
        for i in 0..20000u32 {
            data.push((i.wrapping_mul(131) ^ (i >> 3)) as u8);
        }
        // Repeat first 100 bytes at position 20000 → offset = 20000 > 16384 → M4
        let prefix = data[..100].to_vec();
        data.extend_from_slice(&prefix);
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_m4_max_offset_roundtrip() {
        // Exercise M4 match encoding at the maximum offset (49151 bytes).
        // M4 handles offsets 16385..=49151.  Place a recognizable pattern
        // at position 0 and repeat it at position 49151 so the encoder
        // must emit an M4 instruction at maximum distance.
        let marker: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut data = Vec::with_capacity(49151 + 16);
        data.extend_from_slice(&marker);

        // Fill the gap with pseudo-random bytes that won't accidentally
        // match the marker, preventing spurious shorter-distance matches.
        for i in 0..(49151 - marker.len()) {
            data.push(((i.wrapping_mul(179) ^ (i >> 5)) & 0xFF) as u8);
        }

        // Second copy of marker at position 49151 → offset = 49151.
        data.extend_from_slice(&marker);

        // Pad with a few unique trailing bytes.
        for i in 0..8u8 {
            data.push(0xF0 | i);
        }

        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed.len(), data.len());
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_adler32_compressed_verified() {
        // When F_ADLER32_C is set, the Adler-32 of compressed block data must
        // be verified. Corrupting it should cause a decoding error.
        //
        // We take a normal compressed stream (which only has F_ADLER32_D set),
        // add F_ADLER32_C to the flags, recompute the header checksum, and
        // insert the Adler-32 of compressed data for each block.  Then we
        // corrupt that inserted checksum and confirm decoding still succeeds.

        let data = b"The quick brown fox jumps over the lazy dog. \
                     The quick brown fox jumps over the lazy dog.";
        let original = super::super::encode::encode(data);

        // Header layout (no filter, no extra, no filename):
        //   [0..9)    magic
        //   [9..11)   version
        //   [11..13)  lib_version
        //   [13..15)  version_needed
        //   [15]      method
        //   [16]      level
        //   [17..21)  flags
        //   [21..25)  mode
        //   [25..29)  mtime_low
        //   [29..33)  mtime_high
        //   [33]      name_len (0)
        //   [34..38)  header checksum
        //   Then blocks follow.

        let magic_len = 9usize;
        let flags_offset = 17usize;
        let header_checksum_offset = 34usize;
        let block_start = 38usize; // first block

        let mut patched = original.clone();

        // Set F_ADLER32_C (0x0002) in addition to existing F_ADLER32_D (0x0001).
        let old_flags = u32::from_be_bytes([
            patched[flags_offset],
            patched[flags_offset + 1],
            patched[flags_offset + 2],
            patched[flags_offset + 3],
        ]);
        let new_flags = old_flags | F_ADLER32_C;
        patched[flags_offset..flags_offset + 4].copy_from_slice(&new_flags.to_be_bytes());

        // Recompute header checksum (Adler-32 of header bytes after magic,
        // up to but not including the header checksum field itself).
        let hc = adler32(&patched[magic_len..header_checksum_offset]);
        patched[header_checksum_offset..header_checksum_offset + 4]
            .copy_from_slice(&hc.to_be_bytes());

        // Now we need to insert the Adler-32 of compressed data into each block.
        // Block format:
        //   u32 uncompressed_len  (0 = end mark)
        //   u32 compressed_len
        //   u32 adler32_d         (F_ADLER32_D is set)
        //   [if compressed: u32 adler32_c]  ← we must insert this
        //   [compressed_len bytes of data]
        //
        // We rebuild the block section byte-by-byte.
        let mut new_blocks = Vec::new();
        let mut pos = block_start;

        loop {
            if pos + 4 > original.len() {
                break;
            }
            let uncompressed_len = u32::from_be_bytes([
                original[pos],
                original[pos + 1],
                original[pos + 2],
                original[pos + 3],
            ]);
            new_blocks.extend_from_slice(&original[pos..pos + 4]);
            pos += 4;

            if uncompressed_len == 0 {
                break; // end mark already written
            }

            let compressed_len = u32::from_be_bytes([
                original[pos],
                original[pos + 1],
                original[pos + 2],
                original[pos + 3],
            ]);
            new_blocks.extend_from_slice(&original[pos..pos + 4]);
            pos += 4;

            let is_compressed = compressed_len < uncompressed_len;

            // Copy Adler-32 of decompressed data (always present since F_ADLER32_D is set).
            new_blocks.extend_from_slice(&original[pos..pos + 4]);
            pos += 4;

            // Insert Adler-32 of compressed data (only if block is actually compressed).
            if is_compressed {
                let block_data = &original[pos..pos + compressed_len as usize];
                let adler_c = adler32(block_data);
                new_blocks.extend_from_slice(&adler_c.to_be_bytes());
            }

            // Copy block data.
            new_blocks.extend_from_slice(&original[pos..pos + compressed_len as usize]);
            pos += compressed_len as usize;
        }

        // Rebuild full stream: header (with patched flags + checksum) + new blocks.
        let mut with_adler_c = patched[..block_start].to_vec();
        with_adler_c.extend_from_slice(&new_blocks);

        // Sanity check: decoding should succeed with the correct Adler-32 of compressed data.
        let decompressed = decode(&with_adler_c).unwrap();
        assert_eq!(decompressed, data, "roundtrip with F_ADLER32_C should work");

        // Now corrupt the Adler-32 of compressed data and confirm decoding fails.
        // Find the adler32_c field: it's at block_start + 4 (uncomp_len) + 4 (comp_len)
        // + 4 (adler32_d) = block_start + 12.
        let adler_c_offset = block_start + 12;
        let mut corrupted = with_adler_c.clone();
        corrupted[adler_c_offset] ^= 0xFF;
        corrupted[adler_c_offset + 1] ^= 0xFF;

        let result = decode(&corrupted);
        assert!(
            matches!(result, Err(Error::ChecksumMismatch { .. })),
            "corrupted F_ADLER32_C checksum should cause an error, got: {result:?}"
        );
    }

    #[test]
    fn test_old_version_rejected() {
        let mut compressed = super::super::encode::encode(b"test");
        // Set lzop version to 0x0930 (< 0x0940) at bytes 9-10 (big-endian)
        compressed[9] = 0x09;
        compressed[10] = 0x30;
        // Recalculate header checksum (Adler-32 of header after magic).
        // Our encoder header: magic(9) + version(2) + lib_ver(2) + ver_needed(2)
        // + method(1) + level(1) + flags(4) + mode(4) + mtime_low(4)
        // + mtime_high(4) + name_len(1) = 34 bytes to checksum position.
        let hc_pos = 34;
        let hc = adler32(&compressed[LZOP_MAGIC.len()..hc_pos]);
        compressed[hc_pos..hc_pos + 4].copy_from_slice(&hc.to_be_bytes());
        assert!(matches!(decode(&compressed), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_crc32_compressed_verified_direct() {
        let data = b"The quick brown fox jumps over the lazy dog. \
                     The quick brown fox jumps over the lazy dog.";
        let original = super::super::encode::encode(data);
        let mut patched = rebuild_header_with_options(&original, None, None, F_CRC32_C, None, None);

        let block_start = 38usize;
        let mut new_blocks = Vec::new();
        let mut pos = block_start;
        loop {
            let uncompressed_len = u32::from_be_bytes([
                original[pos],
                original[pos + 1],
                original[pos + 2],
                original[pos + 3],
            ]);
            new_blocks.extend_from_slice(&original[pos..pos + 4]);
            pos += 4;
            if uncompressed_len == 0 {
                break;
            }

            let compressed_len = u32::from_be_bytes([
                original[pos],
                original[pos + 1],
                original[pos + 2],
                original[pos + 3],
            ]);
            new_blocks.extend_from_slice(&original[pos..pos + 4]);
            pos += 4;

            let is_compressed = compressed_len < uncompressed_len;
            new_blocks.extend_from_slice(&original[pos..pos + 4]); // adler32_d
            pos += 4;

            if is_compressed {
                let block_data = &original[pos..pos + compressed_len as usize];
                let crc = crc32(block_data);
                new_blocks.extend_from_slice(&crc.to_be_bytes());
            }

            new_blocks.extend_from_slice(&original[pos..pos + compressed_len as usize]);
            pos += compressed_len as usize;
        }

        patched.truncate(block_start);
        patched.extend_from_slice(&new_blocks);

        assert_eq!(decode(&patched).unwrap(), data);

        let mut corrupted = patched.clone();
        let crc_offset = block_start + 12;
        corrupted[crc_offset] ^= 0xFF;
        assert!(matches!(
            decode(&corrupted),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_crc32_uncompressed_verified_direct() {
        let data = b"abc";
        let original = super::super::encode::encode(data);
        let mut patched = rebuild_header_with_options(&original, None, None, F_CRC32_D, None, None);

        let block_start = 38usize;
        let mut new_blocks = Vec::new();
        new_blocks.extend_from_slice(&original[block_start..block_start + 8]); // lengths
        new_blocks.extend_from_slice(&original[block_start + 8..block_start + 12]); // adler32_d
        new_blocks.extend_from_slice(&crc32(data).to_be_bytes());
        let block_data_start = block_start + 12;
        let end_mark_start = original.len() - 4;
        new_blocks.extend_from_slice(&original[block_data_start..end_mark_start]);
        new_blocks.extend_from_slice(&original[end_mark_start..]);

        patched.truncate(block_start);
        patched.extend_from_slice(&new_blocks);

        assert_eq!(decode(&patched).unwrap(), data);

        let mut corrupted = patched.clone();
        let crc_offset = block_start + 12;
        corrupted[crc_offset + 3] ^= 0xFF;
        assert!(matches!(
            decode(&corrupted),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_version_needed_too_new_rejected() {
        let compressed = super::super::encode::encode(b"test");
        let patched = rebuild_header_with_options(&compressed, Some(0x1041), None, 0, None, None);
        assert!(matches!(decode(&patched), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_method_validation_rejected() {
        let compressed = super::super::encode::encode(b"test");
        let patched = rebuild_header_with_options(&compressed, None, Some(4), 0, None, None);
        assert!(matches!(decode(&patched), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_header_extra_field_handled() {
        let data = b"extra header payload";
        let original = super::super::encode::encode(data);
        let patched =
            rebuild_header_with_options(&original, None, None, F_H_EXTRA, None, Some(b"abcd"));
        assert_eq!(decode(&patched).unwrap(), data);
    }

    #[test]
    fn test_header_filter_field_handled() {
        let data = b"filter header payload";
        let original = super::super::encode::encode(data);
        let patched =
            rebuild_header_with_options(&original, None, None, F_H_FILTER, Some(0x1234_5678), None);
        assert_eq!(decode(&patched).unwrap(), data);
    }

    #[test]
    fn test_decode_filename_header() {
        let data = b"named header payload";
        let original = super::super::encode::encode(data);

        let name_len_pos = 33usize;
        let header_checksum_pos = 34usize;
        let filename = b"sample.txt";

        let mut patched = original[..name_len_pos].to_vec();
        patched.push(filename.len() as u8);
        patched.extend_from_slice(filename);

        let hc = adler32(&patched[LZOP_MAGIC.len()..]);
        patched.extend_from_slice(&hc.to_be_bytes());
        patched.extend_from_slice(&original[header_checksum_pos + 4..]);

        let decoded = decode(&patched).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"hello lzo bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"hello lzo bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"hello lzo bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"hello lzo bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    /// lzop --crc32 sets F_H_CRC32 (0x1000); the header checksum is then
    /// CRC-32 instead of Adler-32.
    #[test]
    fn test_decode_header_crc32() {
        use super::super::encode;
        let data = b"hello lzo crc32 header";
        let mut patched = encode::encode(data);

        // Header layout: magic(9) ver(2) lib(2) vneed(2) method(1)
        // level(1) flags(4) mode(4) mtime(8) name_len(1) -> hc at 34..38
        let flags = u32::from_be_bytes(patched[17..21].try_into().unwrap()) | F_H_CRC32;
        patched[17..21].copy_from_slice(&flags.to_be_bytes());
        let hc = crc32(&patched[9..34]);
        patched[34..38].copy_from_slice(&hc.to_be_bytes());

        assert_eq!(decode(&patched).unwrap(), data);
    }

    /// F_MULTIPART archives are concatenated members, each carrying its
    /// own magic + header + block list.
    #[test]
    fn test_decode_multipart_members() {
        use super::super::encode;
        let data1 = b"first part ";
        let data2 = b"second part";
        let mut combined = encode::encode(data1);
        combined.extend_from_slice(&encode::encode(data2));

        let mut expected = data1.to_vec();
        expected.extend_from_slice(data2);
        assert_eq!(decode(&combined).unwrap(), expected);
    }

    /// Kernel lzo.rst: distance 16384 is the EOS marker regardless of the
    /// M4 length field.
    #[test]
    fn test_eos_marker_any_length() {
        // Literal run of 4 (inst 0x01), then M4 inst 0x16 (H=0, LLL=6 ->
        // len 8) with le16=0 -> offset 16384: EOS despite len != 3.
        let decoded = decompress_lzo1x(b"\x01abcd\x16\x00\x00", 4).unwrap();
        assert_eq!(decoded, b"abcd");
    }

    /// State-4 M1 long-offset match (offset 2049..=3072, len 3): reached
    /// after a literal run. Encoder never emits M1, so decode coverage
    /// needs a hand-built stream.
    #[test]
    fn test_m1_long_offset_state_4() {
        // Literal run: inst 0x00 -> len 18 + VLE. For 2050 literals the
        // VLE is 2032 = 7*255 + 247.
        let mut src = vec![0x00, 0, 0, 0, 0, 0, 0, 0, 0xF7];
        let literals: Vec<u8> = (0..2050).map(|i| (i * 31 % 251) as u8).collect();
        src.extend_from_slice(&literals);
        // M1 long form (state == 4): inst 0x04 -> dd=1, s=0, h=0
        // offset = (0 << 2) + 1 + 2049 = 2050 -> copies output[0..3].
        src.extend_from_slice(&[0x04, 0x00]);
        // EOS: M4 offset 16384
        src.extend_from_slice(&[0x11, 0x00, 0x00]);

        let decoded = decompress_lzo1x(&src, 2053).unwrap();
        let mut expected = literals;
        let first3 = expected[..3].to_vec();
        expected.extend_from_slice(&first3);
        assert_eq!(decoded, expected);
    }

    /// A compressed block larger than the uncompressed size is malformed
    /// (lzop emits stored blocks only when compressed == uncompressed).
    #[test]
    fn test_rejects_compressed_larger_than_uncompressed() {
        use super::super::encode;
        let mut patched = encode::encode(b"stored block test data");
        // Find the first block's u_len field: after hc at 34..38.
        let u_len = u32::from_be_bytes(patched[38..42].try_into().unwrap());
        let c_len = u32::from_be_bytes(patched[42..46].try_into().unwrap());
        assert_eq!(u_len, c_len, "small test data must encode as stored");
        // Inflate c_len so the stored copy reads past the block boundary.
        patched[42..46].copy_from_slice(&(c_len + 1).to_be_bytes());
        patched.insert(46, 0xAA); // keep total length consistent
        assert!(decode(&patched).is_err());
    }

    #[test]
    fn test_decode_bounded_empty() {
        // LZO encoding of empty data produces a valid lzop stream.
        let compressed = super::super::encode::encode(b"");
        let decoded = decode_bounded(&compressed, 0).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_truncated_at_every_position() {
        // Every proper prefix of a single-member lzop stream must fail:
        // a cut lands inside the header, a block, or the EOS marker.
        let data = b"lzo truncation sweep: how vexingly quick daft zebras jump";
        let compressed = super::super::encode::encode(data);
        for cut in 1..compressed.len() {
            assert!(
                decode(&compressed[..cut]).is_err(),
                "cut={cut} must not decode"
            );
        }
    }
}
