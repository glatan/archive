//! gzip decompression per [RFC 1952].
//!
//! Supports multi-member streams and verifies CRC32 checksums and original sizes.
//!
//! [RFC 1952]: https://datatracker.ietf.org/doc/html/rfc1952

use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;

#[cfg(test)]
use crate::compress::deflate::tables::{CODE_LENGTH_ORDER, DISTANCE_EXTRA, LENGTH_EXTRA};
use crate::util::bitreader::BitReader;
use crate::util::crc32;

use super::header::GzipHeader;

/// Decode a gzip compressed byte slice.
///
/// Parses gzip headers, decompresses DEFLATE payloads, and verifies
/// CRC32 checksums and original sizes from trailers. Supports multi-member
/// gzip streams (concatenated gzip members) per RFC 1952 §2.2.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::{encode, decode};
/// use archive::compress::deflate::encode::Level;
///
/// let gz = encode::encode(b"Hello!", Level::Fast);
/// let data = decode::decode(&gz).unwrap();
/// assert_eq!(data, b"Hello!");
/// ```
///
/// # Errors
///
/// Returns [`Error::ChecksumMismatch`] if CRC32 verification fails,
/// [`Error::SizeMismatch`] if the original size does not match.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    decode_into(input, &mut output, None)?;
    Ok(output)
}

/// Append every gzip member in `input` to `output`.
///
/// Each member is a separate DEFLATE stream. It is inflated into its own
/// buffer, so neither a non-empty `output` nor an earlier member is part
/// of the window. `max_output` limits the appended length and is checked
/// after inflation, matching [`decode_bounded`].
pub fn decode_into(
    input: &[u8],
    output: &mut Vec<u8>,
    max_output: Option<usize>,
) -> Result<(), Error> {
    let start = output.len();
    let result = if start == 0 {
        inflate_members(input, output)
    } else {
        let mut fresh = Vec::new();
        inflate_members(input, &mut fresh)?;
        output.extend_from_slice(&fresh);
        Ok(())
    };
    if result.is_err() {
        output.truncate(start);
        return result;
    }
    if let Some(limit) = max_output
        && output.len() - start > limit
    {
        output.truncate(start);
        return Err(Error::OutputLimitExceeded { limit });
    }
    Ok(())
}

fn inflate_members(input: &[u8], output: &mut Vec<u8>) -> Result<(), Error> {
    let mut pos = 0;

    while pos < input.len() {
        let member_data = &input[pos..];
        let header = GzipHeader::parse(member_data)?;
        let compressed_start = header.header_size;
        let compressed_data = &member_data[compressed_start..];

        let mut member_out = Vec::new();
        let mut reader = BitReader::new(compressed_data);
        deflate::decode::decode_stream(&mut reader, &mut member_out)?;
        reader.align_to_byte();
        let trailer_start = reader.byte_position() + compressed_start;

        if trailer_start + 8 > member_data.len() {
            return Err(Error::UnexpectedEof);
        }

        let expected_crc = u32::from_le_bytes([
            member_data[trailer_start],
            member_data[trailer_start + 1],
            member_data[trailer_start + 2],
            member_data[trailer_start + 3],
        ]);
        let expected_size = u32::from_le_bytes([
            member_data[trailer_start + 4],
            member_data[trailer_start + 5],
            member_data[trailer_start + 6],
            member_data[trailer_start + 7],
        ]);

        let actual_crc = crc32::crc32(&member_out);
        if actual_crc != expected_crc {
            return Err(Error::ChecksumMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        verify_isize(member_out.len(), expected_size)?;
        output.extend_from_slice(&member_out);

        pos += trailer_start + 8;
    }

    Ok(())
}

const fn verify_isize(actual_len: usize, expected_size: u32) -> Result<(), Error> {
    let actual_size = actual_len as u32;
    if actual_size != expected_size {
        return Err(Error::SizeMismatch {
            expected: expected_size,
            actual: actual_size,
        });
    }
    Ok(())
}

#[cfg(test)]
/// Find the byte position where the DEFLATE stream ends.
/// This re-parses the DEFLATE blocks to find boundaries.
fn find_deflate_end(data: &[u8]) -> Result<usize, Error> {
    use crate::compress::deflate::tables::*;
    use crate::util::bitreader::BitReader;

    let mut reader = BitReader::new(data);

    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;

        match btype {
            0b00 => {
                // Uncompressed
                reader.align_to_byte();
                let len = reader.read_u16_le()?;
                let nlen = reader.read_u16_le()?;
                if len != !nlen {
                    return Err(Error::InvalidData("stored block LEN/NLEN mismatch"));
                }
                let _ = reader.read_bytes(len as usize)?;
            }
            0b01 => {
                // Fixed Huffman
                skip_huffman_block(
                    &mut reader,
                    &fixed_literal_lengths(),
                    &fixed_distance_lengths(),
                )?;
            }
            0b10 => {
                // Dynamic Huffman - we need to parse the tables then skip the block
                skip_dynamic_huffman_block(&mut reader)?;
            }
            _ => return Err(Error::InvalidData("invalid DEFLATE block type")),
        }

        if bfinal == 1 {
            break;
        }
    }

    reader.align_to_byte();
    Ok(reader.byte_position())
}

#[cfg(test)]
/// Build a simple Huffman table and skip through a Huffman-coded block.
fn skip_huffman_block(
    reader: &mut BitReader,
    lit_lengths: &[u8],
    dist_lengths: &[u8],
) -> Result<(), Error> {
    // We reuse the same HuffmanTable from the decode module
    // But to avoid circular deps, we inline a minimal version here
    let lit_table = SimpleHuffman::from_lengths(lit_lengths)?;
    let dist_table = SimpleHuffman::from_lengths(dist_lengths)?;

    loop {
        let symbol = lit_table.decode(reader)?;
        match symbol {
            0..=255 => {}         // literal, skip
            256 => return Ok(()), // end of block
            257..=285 => {
                let len_idx = (symbol - 257) as usize;
                let _extra = reader.read_bits(LENGTH_EXTRA[len_idx])?;
                let dist_sym = dist_table.decode(reader)? as usize;
                if dist_sym < DISTANCE_EXTRA.len() {
                    let _extra = reader.read_bits(DISTANCE_EXTRA[dist_sym])?;
                }
            }
            _ => return Err(Error::InvalidData("invalid symbol")),
        }
    }
}

#[cfg(test)]
fn skip_dynamic_huffman_block(reader: &mut BitReader) -> Result<(), Error> {
    let hlit = reader.read_bits(5)? as usize + 257;
    let hdist = reader.read_bits(5)? as usize + 1;
    let hclen = reader.read_bits(4)? as usize + 4;

    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CODE_LENGTH_ORDER[i]] = reader.read_bits(3)? as u8;
    }

    let cl_table = SimpleHuffman::from_lengths(&cl_lengths)?;

    let total = hlit + hdist;
    let mut lengths = alloc::vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = cl_table.decode(reader)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                let repeat = reader.read_bits(2)? as usize + 3;
                let prev = if i > 0 { lengths[i - 1] } else { 0 };
                for _ in 0..repeat {
                    if i >= total {
                        return Err(Error::InvalidData("code length repeat overflow"));
                    }
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let count = reader.read_bits(3)? as usize + 3;
                i += count;
                if i > total {
                    return Err(Error::InvalidData("code length repeat overflow"));
                }
            }
            18 => {
                let count = reader.read_bits(7)? as usize + 11;
                i += count;
                if i > total {
                    return Err(Error::InvalidData("code length repeat overflow"));
                }
            }
            _ => return Err(Error::InvalidData("invalid code length symbol")),
        }
    }

    skip_huffman_block(reader, &lengths[..hlit], &lengths[hlit..hlit + hdist])
}

/// Minimal Huffman table for stream-skipping in gzip trailer search.
#[cfg(test)]
struct SimpleHuffman {
    entries: alloc::vec::Vec<(u16, u8)>,
    max_bits: u8,
}

#[cfg(test)]
impl SimpleHuffman {
    fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        let max_bits = *code_lengths.iter().max().unwrap_or(&0);
        if max_bits == 0 {
            return Ok(Self {
                entries: alloc::vec::Vec::new(),
                max_bits: 0,
            });
        }
        if max_bits > 15 {
            return Err(Error::InvalidData("code length exceeds 15"));
        }

        let mut bl_count = [0u32; 16];
        for &len in code_lengths {
            bl_count[len as usize] += 1;
        }
        bl_count[0] = 0;

        let mut next_code = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..=max_bits {
            code = (code + bl_count[(bits - 1) as usize]) << 1;
            next_code[bits as usize] = code;
        }

        let table_size = 1usize << max_bits;
        let mut entries = alloc::vec![(0u16, 0u8); table_size];

        for (symbol, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let c = next_code[len as usize];
            next_code[len as usize] += 1;
            let reversed = reverse_bits_simple(c, len);
            let step = 1usize << len;
            let mut idx = reversed as usize;
            while idx < table_size {
                entries[idx] = (symbol as u16, len);
                idx += step;
            }
        }

        Ok(Self { entries, max_bits })
    }

    fn decode(&self, reader: &mut BitReader) -> Result<u16, Error> {
        let bits = reader.peek_bits(self.max_bits)? as usize;
        let (symbol, len) = self.entries[bits];
        if len == 0 {
            return Err(Error::InvalidData("invalid Huffman code"));
        }
        reader.consume(len);
        Ok(symbol)
    }
}

#[cfg(test)]
fn reverse_bits_simple(value: u32, num_bits: u8) -> u32 {
    let mut result = 0;
    let mut v = value;
    for _ in 0..num_bits {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }
    result
}

/// Decode gzip compressed data from a [`std::io::Read`] source.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if reading from the source fails, or if the data is malformed.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::{encode, decode};
/// use archive::compress::deflate::encode::Level;
///
/// let gz = encode::encode(b"data", Level::Fast);
/// let data = decode::decode_reader(gz.as_slice()).unwrap();
/// assert_eq!(data, b"data");
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> Result<Vec<u8>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

/// Decode with a maximum output size limit.
///
/// Returns `Error::OutputLimitExceeded` if the decompressed output
/// would exceed `max_output` bytes.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    decode_into(input, &mut output, Some(max_output))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::deflate::encode::Level;
    use crate::compress::gzip::encode;

    #[test]
    fn test_decode_into_appends_without_touching_prefix() {
        let compressed = encode::encode(b"hello hello hello", Level::Fast);
        let mut output = b"prefix".to_vec();
        decode_into(&compressed, &mut output, None).unwrap();
        assert_eq!(output, b"prefixhello hello hello");

        let mut limited = Vec::new();
        let err = decode_into(&compressed, &mut limited, Some(1));
        assert!(matches!(err, Err(Error::OutputLimitExceeded { limit: 1 })));
        assert!(limited.is_empty());

        let mut broken = output.clone();
        assert!(decode_into(&[0x1F, 0x8B], &mut broken, None).is_err());
        assert_eq!(broken, output);
    }

    // Phase 1: Error detection

    #[test]
    fn test_crc32_mismatch() {
        let input = b"Hello, gzip!";
        let mut encoded = encode::encode(input, Level::Fast);
        // Corrupt the CRC32 in the trailer (last 8 bytes: CRC32 + ISIZE)
        let crc_pos = encoded.len() - 8;
        encoded[crc_pos] ^= 0xFF; // flip bits in CRC
        let result = decode(&encoded);
        assert!(matches!(result, Err(Error::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_isize_mismatch() {
        let input = b"Hello, gzip!";
        let mut encoded = encode::encode(input, Level::Fast);
        // Corrupt the ISIZE in the trailer (last 4 bytes)
        let isize_pos = encoded.len() - 4;
        encoded[isize_pos] ^= 0xFF;
        let result = decode(&encoded);
        // Could be either SizeMismatch or ChecksumMismatch depending on which check fails first
        // CRC is checked first, so if CRC still matches (unlikely after ISIZE corruption only),
        // we get SizeMismatch. Since we only changed ISIZE, CRC should still pass.
        assert!(matches!(result, Err(Error::SizeMismatch { .. })));
    }

    // Phase 3: Multi-member

    #[test]
    fn test_multi_member_gzip() {
        // Create two gzip members concatenated (RFC 1952 §2.2)
        let member1 = encode::encode(b"Hello", Level::NoCompression);
        let member2 = encode::encode(b" World", Level::NoCompression);
        let mut combined = member1.clone();
        combined.extend_from_slice(&member2);
        let result = decode(&combined).unwrap();
        assert_eq!(result, b"Hello World");
    }

    /// A match in the second member must not read the first member.
    /// The trailer describes the bytes that leak would produce, so a
    /// window that crosses the member boundary would decode successfully.
    #[test]
    fn test_multi_member_distance_does_not_cross_boundary() {
        use crate::compress::deflate::tables::reverse_bits;

        let member1 = encode::encode(b"Hello", Level::NoCompression);
        let mut bits = Vec::new();
        let mut acc = 0u32;
        let mut n = 0u8;
        let mut write = |value: u32, width: u8| {
            acc |= value << n;
            n += width;
            while n >= 8 {
                bits.push(acc as u8);
                acc >>= 8;
                n -= 8;
            }
        };
        write(1, 1);
        write(0b01, 2);
        write(reverse_bits(257 - 256, 7), 7);
        write(reverse_bits(0, 5), 5);
        write(reverse_bits(0, 7), 7);
        if n > 0 {
            bits.push(acc as u8);
        }

        let leaked = b"ooo";
        let crc = crate::util::crc32::crc32(leaked);
        let mut member2 = vec![0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF];
        member2.extend_from_slice(&bits);
        member2.extend_from_slice(&crc.to_le_bytes());
        member2.extend_from_slice(&3u32.to_le_bytes());

        let mut combined = member1;
        combined.extend_from_slice(&member2);
        let err = decode(&combined).unwrap_err();
        assert!(
            matches!(err, Error::InvalidData("distance too far back")),
            "{err:?}"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader() {
        let input = b"Hello, gzip!";
        let encoded = encode::encode(input, Level::Fast);
        let cursor = std::io::Cursor::new(&encoded);
        let decoded = decode_reader(cursor).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_multi_member_gzip_three_members() {
        let m1 = encode::encode(b"A", Level::NoCompression);
        let m2 = encode::encode(b"B", Level::Fast);
        let m3 = encode::encode(b"C", Level::NoCompression);
        let mut combined = m1;
        combined.extend_from_slice(&m2);
        combined.extend_from_slice(&m3);
        let result = decode(&combined).unwrap();
        assert_eq!(result, b"ABC");
    }

    #[test]
    fn test_truncated_deflate_stream() {
        let input = b"Hello, gzip!";
        let encoded = encode::encode(input, Level::Fast);
        // Truncate: keep gzip header but cut off DEFLATE data partway through
        // A gzip header is at least 10 bytes; cut a few bytes into the DEFLATE stream
        let truncated = &encoded[..encoded.len().min(15)];
        let result = decode(truncated);
        assert!(result.is_err(), "decoding a truncated stream should fail");
    }

    #[test]
    fn test_multi_member_different_compression() {
        let m1 = encode::encode(b"stored", Level::NoCompression);
        let m2 = encode::encode(b" compressed", Level::Fast);
        let mut combined = m1;
        combined.extend_from_slice(&m2);
        let result = decode(&combined).unwrap();
        assert_eq!(result, b"stored compressed");
    }

    #[test]
    fn test_header_truncated() {
        // Less than 10 bytes (minimum gzip header)
        let result = decode(&[0x1f, 0x8b, 0x08, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_trailer_truncated_no_isize() {
        let input = b"Hello";
        let encoded = encode::encode(input, Level::NoCompression);
        // Remove last 4 bytes (ISIZE), keep CRC32
        let truncated = &encoded[..encoded.len() - 4];
        let result = decode(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_member_with_fname() {
        use crate::compress::gzip::encode::{GzipEncodeOptions, encode_with_options};

        let opts1 = GzipEncodeOptions {
            filename: Some("file1.txt"),
            ..Default::default()
        };
        let opts2 = GzipEncodeOptions {
            filename: Some("file2.txt"),
            ..Default::default()
        };
        let m1 = encode_with_options(b"Hello", Level::NoCompression, &opts1).unwrap();
        let m2 = encode_with_options(b" World", Level::NoCompression, &opts2).unwrap();
        let mut combined = m1;
        combined.extend_from_slice(&m2);
        let result = decode(&combined).unwrap();
        assert_eq!(result, b"Hello World");
    }

    // C-5 #29: empty input
    #[test]
    fn test_decode_empty_input() {
        let result = decode(&[]);
        // Empty input should return empty or error, but not panic
        if let Ok(data) = result {
            assert!(data.is_empty());
        }
    }

    // C-5 #32: empty input roundtrip with Fast and Default levels
    #[test]
    fn test_encode_decode_empty_input() {
        for level in [Level::NoCompression, Level::Fast, Level::Default] {
            let encoded = crate::compress::gzip::encode::encode(&[], level);
            let decoded = decode(&encoded).unwrap();
            assert!(
                decoded.is_empty(),
                "empty input roundtrip failed for {level:?}"
            );
        }
    }

    #[test]
    fn test_multi_member_mixed_flags() {
        use crate::compress::gzip::encode::{GzipEncodeOptions, encode_with_options};

        // First member: FNAME flag set
        let opts1 = GzipEncodeOptions {
            filename: Some("part1.dat"),
            ..Default::default()
        };
        let m1 = encode_with_options(b"first", Level::Fast, &opts1).unwrap();

        // Second member: FCOMMENT flag set
        let opts2 = GzipEncodeOptions {
            comment: Some("second member comment"),
            ..Default::default()
        };
        let m2 = encode_with_options(b"second", Level::Default, &opts2).unwrap();

        let mut combined = m1;
        combined.extend_from_slice(&m2);

        let result = decode(&combined).unwrap();
        assert_eq!(result, b"firstsecond");
    }

    #[test]
    fn test_deflate_end_detection_bit_boundary() {
        // Use a fixed-Huffman DEFLATE block (Level::Fast) so the BFINAL block
        // ends at a non-byte-aligned bit position. After the end-of-block
        // symbol (256), the bit reader must align to the next byte boundary
        // before the trailer. Varying input lengths exercise different bit
        // positions for the final symbol.
        //
        // We test several small inputs whose DEFLATE encodings end at
        // different sub-byte offsets.
        let test_inputs: &[&[u8]] = &[
            b"A",
            b"AB",
            b"ABC",
            b"ABCD",
            b"ABCDE",
            b"a",            // single lowercase
            b"\x00\x01\x02", // non-ASCII bytes
        ];

        for input in test_inputs {
            let encoded = encode::encode(input, Level::Fast);

            // Verify the DEFLATE data (after 10-byte header) is NOT byte-aligned
            // by checking that the total encoded size differs from what a stored
            // block would produce (10 header + 5 block header + N data + 8 trailer).
            let stored_size = 10 + 5 + input.len() + 8;
            assert_ne!(
                encoded.len(),
                stored_size,
                "Fixed-Huffman encoding for {:?} should differ from stored-block size",
                input
            );

            // The actual test: decoding must succeed and roundtrip correctly
            let decoded = decode(&encoded).unwrap();
            assert_eq!(
                decoded, *input,
                "Bit-boundary roundtrip failed for {:?}",
                input
            );
        }
    }

    #[test]
    fn test_ftext_flag_ignored() {
        // RFC 1952 §2.3.1.1: FTEXT (bit 0) is informational and must be ignored
        let input = b"hello";
        let mut encoded = crate::compress::gzip::encode::encode(input, Level::Default);
        // Set FTEXT flag (bit 0) in FLG byte (offset 3)
        encoded[3] |= 0x01;
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input, "FTEXT flag should be ignored by decoder");
    }

    #[test]
    fn test_verify_isize_modulo_wrap_accepts_4gib_boundary() {
        let wrapped_len = ((1u64 << 32) + 256) as usize;
        assert_eq!(verify_isize(wrapped_len, 256), Ok(()));
    }

    #[test]
    fn test_valid_trailer_crc32_and_isize() {
        let input = b"Hello, gzip trailer!";
        let encoded = encode::encode(input, Level::Fast);
        let trailer_start = find_deflate_end(&encoded[10..]).unwrap() + 10;

        let expected_crc = u32::from_le_bytes([
            encoded[trailer_start],
            encoded[trailer_start + 1],
            encoded[trailer_start + 2],
            encoded[trailer_start + 3],
        ]);
        let expected_size = u32::from_le_bytes([
            encoded[trailer_start + 4],
            encoded[trailer_start + 5],
            encoded[trailer_start + 6],
            encoded[trailer_start + 7],
        ]);

        assert_eq!(expected_crc, crate::util::crc32::crc32(input));
        assert_eq!(expected_size, input.len() as u32);
        assert_eq!(decode(&encoded).unwrap(), input);
    }

    #[test]
    fn test_verify_isize_modulo_wrap_mismatch() {
        let wrapped_len = ((1u64 << 32) + 256) as usize;
        assert_eq!(
            verify_isize(wrapped_len, 257),
            Err(Error::SizeMismatch {
                expected: 257,
                actual: 256,
            })
        );
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = encode::encode(data, Level::Default);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = encode::encode(data, Level::Default);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = encode::encode(data, Level::Default);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = encode::encode(data, Level::Default);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_trailing_garbage_after_member_rejected() {
        // Strict RFC 1952 §2.2 interpretation: bytes after the last member
        // are parsed as a new member, so garbage trailing data is rejected.
        let mut encoded = encode::encode(b"data", Level::Fast);
        encoded.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn test_truncated_at_every_position() {
        // Every proper prefix of a valid gzip stream must fail.
        let data = b"gzip truncation boundary test payload";
        let encoded = encode::encode(data, Level::Fast);
        for cut in 1..encoded.len() {
            assert!(
                decode(&encoded[..cut]).is_err(),
                "cut={cut} must not decode"
            );
        }
    }

    #[test]
    fn test_multi_member_second_member_invalid() {
        // A malformed second member must fail the whole decode even though
        // the first member is intact.
        let member1 = encode::encode(b"first", Level::Fast);
        let mut combined = member1;
        // Second "member" with valid magic but invalid method byte.
        combined.extend_from_slice(&[0x1F, 0x8B, 0x07, 0x00, 0, 0, 0, 0, 0, 0]);
        assert!(decode(&combined).is_err());
    }
}
