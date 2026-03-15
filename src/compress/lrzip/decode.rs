//! lrzip decompression.
//!
//! Decodes the crate's lrzip streams and the currently validated subset of
//! system `lrzip` `.lrz` files.
//!
//! Within the crate-local container contract, supported backend compression
//! types are LZMA, bzip2, LZO, zlib/gzip, ZPAQ, and none.
//!
//! For system `lrzip` interoperability, the current test coverage confirms both
//! simple and match-rich LZMA-authored `.lrz` inputs. The decode path parses
//! lrzip's variable-width match offset field (`chunk_bytes`) instead of
//! assuming the fixed-width upstream `.rz` token stream.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lrzip::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::compress::lzma::LzmaProperties;
use crate::compress::rzip;
use crate::error::Error;

/// lrzip file magic number: "LRZI".
const MAGIC: &[u8; 4] = b"LRZI";

/// Maximum supported major version.
const MAX_VERSION_MAJOR: u8 = 0;

/// Number of streams per chunk.
const NUM_STREAMS: usize = 2;

/// Compression type values.
const CTYPE_NONE: u8 = 3;
const CTYPE_BZIP2: u8 = 4;
const CTYPE_LZO: u8 = 5;
const CTYPE_LZMA: u8 = 6;
const CTYPE_GZIP: u8 = 7;
const CTYPE_ZPAQ: u8 = 8;

/// Decode lrzip format data.
///
/// Supports all backend compression types.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if the data is not valid lrzip format.
///
/// # Examples
///
/// ```
/// use archive::compress::lrzip::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() < 24 {
        return Err(Error::InvalidData("lrzip: input too short for header"));
    }

    // ── File header (24 bytes) ──────────────────────────────────
    if &input[0..4] != MAGIC {
        return Err(Error::InvalidData("lrzip: invalid magic number"));
    }

    let major = input[4];
    if major > MAX_VERSION_MAJOR {
        return Err(Error::Unsupported("lrzip: unsupported version"));
    }

    let _minor = input[5];

    let total_size = u64::from_le_bytes([
        input[6], input[7], input[8], input[9], input[10], input[11], input[12], input[13],
    ]);

    // Bytes 14-15: unused
    // Bytes 16-20: LZMA properties (used when decompressing LZMA blocks)
    // Byte 16 = props_byte, Bytes 17-20 = dict_size (LE)
    let props_byte = input[16];
    let lzma_props = LzmaProperties::from_props_byte(props_byte)
        .map_err(|_| Error::InvalidData("lrzip: invalid LZMA properties"))?;
    let dict_size = u32::from_le_bytes([input[17], input[18], input[19], input[20]]);

    let md5_flag = input[21];
    let encrypt_flag = input[22];
    if encrypt_flag != 0 {
        return Err(Error::Unsupported("lrzip: encrypted files not supported"));
    }

    let mut output = Vec::with_capacity(total_size.min(4 * 1024 * 1024) as usize);
    let mut pos = 24;

    // ── Process chunks ──────────────────────────────────────────
    loop {
        if pos >= input.len() {
            break;
        }

        // Chunk header
        if pos + 2 > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let chunk_bytes = input[pos] as usize;
        let eof = input[pos + 1];
        pos += 2;

        if chunk_bytes == 0 || chunk_bytes > 8 {
            return Err(Error::InvalidData("lrzip: invalid chunk_bytes"));
        }

        if pos + chunk_bytes > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let chunk_size = rzip::decode::read_le_n_at(input, &mut pos, chunk_bytes)?;
        let chunk_base = pos;

        // Read stream headers
        let mut stream_last_heads = [0u64; NUM_STREAMS];
        let mut chunk_data_end = pos;

        for last_head in stream_last_heads.iter_mut().take(NUM_STREAMS) {
            if pos + 1 + 3 * chunk_bytes > input.len() {
                return Err(Error::UnexpectedEof);
            }
            let _ctype = input[pos];
            pos += 1;
            let _c_len = rzip::decode::read_le_n_at(input, &mut pos, chunk_bytes)?;
            let _u_len = rzip::decode::read_le_n_at(input, &mut pos, chunk_bytes)?;
            *last_head = rzip::decode::read_le_n_at(input, &mut pos, chunk_bytes)?;
        }

        // Read data blocks for each stream by following last_head chain
        let mut stream_data = [Vec::new(), Vec::new()];
        for i in 0..NUM_STREAMS {
            let mut block_offset =
                resolve_block_offset(stream_last_heads[i], chunk_base, input.len(), chunk_bytes)?;
            let mut block_count = 0u32;

            while block_offset != 0 {
                block_count += 1;
                if block_count > 10000 {
                    return Err(Error::InvalidData("lrzip: block chain cycle detected"));
                }

                if block_offset + 1 + 3 * chunk_bytes > input.len() {
                    return Err(Error::UnexpectedEof);
                }

                let mut bpos = block_offset;
                let block_ctype = input[bpos];
                bpos += 1;
                let block_c_len = rzip::decode::read_le_n_at(input, &mut bpos, chunk_bytes)?;
                let block_u_len = rzip::decode::read_le_n_at(input, &mut bpos, chunk_bytes)?;
                let next_head = rzip::decode::read_le_n_at(input, &mut bpos, chunk_bytes)?;

                if bpos + block_c_len as usize > input.len() {
                    return Err(Error::UnexpectedEof);
                }

                let block_data = &input[bpos..bpos + block_c_len as usize];
                chunk_data_end = chunk_data_end.max(bpos + block_c_len as usize);

                // Decompress block based on ctype
                let decompressed =
                    decompress_block(block_data, block_ctype, dict_size, lzma_props, block_u_len)?;
                stream_data[i].extend_from_slice(&decompressed);

                block_offset =
                    resolve_block_offset(next_head, chunk_base, input.len(), chunk_bytes)?;
            }
        }

        // Decode rzip token stream
        if chunk_size == 0 && stream_data[0].len() == 4 && stream_data[1].is_empty() {
            let expected_crc = u32::from_le_bytes([
                stream_data[0][0],
                stream_data[0][1],
                stream_data[0][2],
                stream_data[0][3],
            ]);
            let actual_crc = rzip::legacy_crc32(&[]);
            if actual_crc != expected_crc {
                return Err(Error::ChecksumMismatch {
                    expected: expected_crc,
                    actual: actual_crc,
                });
            }
        } else {
            decode_chunk_streams(&stream_data[0], &stream_data[1], chunk_bytes, &mut output)?;
        }

        pos = chunk_data_end;

        if eof != 0 {
            break;
        }
    }

    if output.len() as u64 != total_size {
        return Err(Error::InvalidData("lrzip: output size mismatch"));
    }

    // Verify the file-level MD5 checksum when the flag is set (RFC 1321).
    // The 16-byte digest is stored immediately after the last chunk, starting
    // at `pos`.
    if md5_flag != 0 {
        if pos + 16 > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let expected: [u8; 16] = input[pos..pos + 16].try_into().unwrap();
        let actual = crate::util::md5::md5(&output);
        if actual != expected {
            return Err(Error::InvalidData("lrzip: MD5 checksum mismatch"));
        }
    }

    Ok(output)
}

fn decode_chunk_streams(
    stream0: &[u8],
    stream1: &[u8],
    chunk_bytes: usize,
    dst: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut s0pos = 0usize;
    let mut s1pos = 0usize;
    let chunk_start = dst.len();

    while s0pos + 3 <= stream0.len() {
        let head = stream0[s0pos];
        let length = u16::from_le_bytes([stream0[s0pos + 1], stream0[s0pos + 2]]) as usize;
        s0pos += 3;

        match head {
            0x00 if length == 0 => {
                if s0pos + 4 > stream0.len() {
                    return Err(Error::InvalidData("lrzip: missing CRC in stream"));
                }
                let expected_crc = u32::from_le_bytes([
                    stream0[s0pos],
                    stream0[s0pos + 1],
                    stream0[s0pos + 2],
                    stream0[s0pos + 3],
                ]);
                let actual_crc = rzip::legacy_crc32(&dst[chunk_start..]);
                if actual_crc != expected_crc {
                    return Err(Error::ChecksumMismatch {
                        expected: expected_crc,
                        actual: actual_crc,
                    });
                }
                return Ok(());
            }
            0x00 => {
                if s1pos + length > stream1.len() {
                    return Err(Error::UnexpectedEof);
                }
                dst.extend_from_slice(&stream1[s1pos..s1pos + length]);
                s1pos += length;
            }
            _ => {
                if s0pos + chunk_bytes > stream0.len() {
                    return Err(Error::UnexpectedEof);
                }
                let mut offset_bytes = [0u8; 8];
                offset_bytes[..chunk_bytes].copy_from_slice(&stream0[s0pos..s0pos + chunk_bytes]);
                let offset = u64::from_le_bytes(offset_bytes) as usize;
                s0pos += chunk_bytes;

                let current_pos = dst.len() - chunk_start;
                if offset == 0 || offset > current_pos {
                    return Err(Error::InvalidData("rzip: match offset out of range"));
                }

                let match_start = dst.len() - offset;
                for i in 0..length {
                    let b = dst[match_start + i];
                    dst.push(b);
                }
            }
        }
    }

    Err(Error::InvalidData("lrzip: unterminated chunk stream"))
}

/// Decompress a single block based on compression type.
fn decompress_block(
    data: &[u8],
    ctype: u8,
    dict_size: u32,
    lzma_props: LzmaProperties,
    u_len: u64,
) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    match ctype {
        CTYPE_NONE => Ok(data.to_vec()),
        CTYPE_BZIP2 => crate::compress::bzip2::decode::decode(data),
        CTYPE_LZO => crate::compress::lzo::decode::decompress_lzo1x(data, u_len as usize),
        CTYPE_LZMA => {
            let (decoded, _consumed) =
                crate::compress::lzma::lzma_decode_with_props(data, dict_size, lzma_props)?;
            Ok(decoded)
        }
        CTYPE_GZIP => crate::compress::zlib::decode::decode(data),
        CTYPE_ZPAQ => crate::compress::zpaq::decode::decode(data),
        _ => Err(Error::Unsupported("lrzip: unsupported compression type")),
    }
}

/// Decode lrzip format data from a reader.
///
/// # Errors
///
/// Returns an error if reading fails or the data is not valid lrzip format.
///
/// # Examples
///
/// ```
/// use archive::compress::lrzip::{decode, encode};
///
/// let data = b"Hello, reader!";
/// let compressed = encode::encode(data);
/// let decoded = decode::decode_reader(&compressed[..]).unwrap();
/// assert_eq!(decoded, data);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    decode_to_writer(&mut reader, &mut output)?;
    Ok(output)
}

/// Decode lrzip format data from a reader into a writer without buffering the
/// entire compressed input in memory.
#[cfg(feature = "std")]
pub fn decode_to_writer<R: std::io::Read, W: std::io::Write>(
    mut reader: R,
    mut writer: W,
) -> std::io::Result<()> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let total_size = parse_header(&header).map_err(std::io::Error::from)?;
    let lzma_props = LzmaProperties::from_props_byte(header[16])
        .map_err(|_| Error::InvalidData("lrzip: invalid LZMA properties"))
        .map_err(std::io::Error::from)?;
    let dict_size = u32::from_le_bytes([header[17], header[18], header[19], header[20]]);

    let mut total_written = 0u64;
    loop {
        let mut chunk_header = [0u8; 2];
        reader.read_exact(&mut chunk_header)?;
        let chunk_bytes = chunk_header[0] as usize;
        let eof = chunk_header[1] != 0;
        if chunk_bytes == 0 || chunk_bytes > 8 {
            return Err(std::io::Error::from(Error::InvalidData(
                "lrzip: invalid chunk_bytes",
            )));
        }
        let chunk_size = read_le_n_from_reader(&mut reader, chunk_bytes)?;

        let mut stream_headers = [(0u8, 0u64, 0u64); NUM_STREAMS];
        for header in &mut stream_headers {
            let mut ctype = [0u8; 1];
            reader.read_exact(&mut ctype)?;
            *header = (
                ctype[0],
                read_le_n_from_reader(&mut reader, chunk_bytes)?,
                read_le_n_from_reader(&mut reader, chunk_bytes)?,
            );
            let _last_head = read_le_n_from_reader(&mut reader, chunk_bytes)?;
        }

        let mut stream_data = [Vec::new(), Vec::new()];
        for (stream_index, &(header_ctype, header_c_len, header_u_len)) in
            stream_headers.iter().enumerate()
        {
            let mut ctype = [0u8; 1];
            reader.read_exact(&mut ctype)?;
            let block_ctype = ctype[0];
            let block_c_len = read_le_n_from_reader(&mut reader, chunk_bytes)?;
            let block_u_len = read_le_n_from_reader(&mut reader, chunk_bytes)?;
            let next_head = read_le_n_from_reader(&mut reader, chunk_bytes)?;
            if next_head != 0 {
                return Err(std::io::Error::from(Error::Unsupported(
                    "lrzip: streaming decode does not support multi-block chunks",
                )));
            }
            if block_ctype != header_ctype
                || (header_c_len != 0 && block_c_len != header_c_len)
                || (header_u_len != 0 && block_u_len != header_u_len)
            {
                return Err(std::io::Error::from(Error::InvalidData(
                    "lrzip: stream header/block header mismatch",
                )));
            }

            let mut block_data = vec![0u8; block_c_len as usize];
            reader.read_exact(&mut block_data)?;
            stream_data[stream_index] =
                decompress_block(&block_data, block_ctype, dict_size, lzma_props, block_u_len)
                    .map_err(std::io::Error::from)?;
        }

        if chunk_size == 0 && stream_data[0].len() == 4 && stream_data[1].is_empty() {
            let expected_crc = u32::from_le_bytes([
                stream_data[0][0],
                stream_data[0][1],
                stream_data[0][2],
                stream_data[0][3],
            ]);
            let actual_crc = rzip::legacy_crc32(&[]);
            if actual_crc != expected_crc {
                return Err(std::io::Error::from(Error::ChecksumMismatch {
                    expected: expected_crc,
                    actual: actual_crc,
                }));
            }
        } else {
            let mut chunk_output = Vec::with_capacity(chunk_size as usize);
            decode_chunk_streams(
                &stream_data[0],
                &stream_data[1],
                chunk_bytes,
                &mut chunk_output,
            )
            .map_err(std::io::Error::from)?;
            if chunk_size != 0 && chunk_output.len() as u64 != chunk_size {
                return Err(std::io::Error::from(Error::InvalidData(
                    "lrzip: chunk size mismatch",
                )));
            }
            writer.write_all(&chunk_output)?;
            total_written = total_written
                .checked_add(chunk_output.len() as u64)
                .ok_or_else(|| {
                    std::io::Error::from(Error::InvalidData("lrzip: output size overflow"))
                })?;
        }

        if eof {
            break;
        }
    }

    if total_written != total_size {
        return Err(std::io::Error::from(Error::InvalidData(
            "lrzip: output size mismatch",
        )));
    }
    Ok(())
}

fn parse_header(header: &[u8; 24]) -> Result<u64, Error> {
    if &header[0..4] != MAGIC {
        return Err(Error::InvalidData("lrzip: invalid magic number"));
    }

    if header[4] > MAX_VERSION_MAJOR {
        return Err(Error::Unsupported("lrzip: unsupported version"));
    }

    if header[22] != 0 {
        return Err(Error::Unsupported("lrzip: encrypted files not supported"));
    }

    Ok(u64::from_le_bytes([
        header[6], header[7], header[8], header[9], header[10], header[11], header[12], header[13],
    ]))
}

const fn resolve_block_offset(
    stored: u64,
    chunk_base: usize,
    input_len: usize,
    chunk_bytes: usize,
) -> Result<usize, Error> {
    if stored == 0 {
        return Ok(0);
    }
    let offset = stored as usize;
    let header_size = 1 + 3 * chunk_bytes;
    if let Some(relative) = chunk_base.checked_add(offset)
        && relative + header_size <= input_len
    {
        return Ok(relative);
    }
    if offset + header_size <= input_len {
        return Ok(offset);
    }
    Err(Error::InvalidData("lrzip: block offset overflow"))
}

#[cfg(feature = "std")]
fn read_le_n_from_reader<R: std::io::Read>(reader: &mut R, n: usize) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf[..n])?;
    Ok(buf[..n]
        .iter()
        .enumerate()
        .fold(0u64, |acc, (i, &byte)| acc | ((byte as u64) << (8 * i))))
}

/// Decode with a maximum output size limit.
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
    use crate::compress::lzma::{self, LzmaProperties};
    #[cfg(feature = "std")]
    use std::io::Cursor;

    fn read_le_n_test(data: &[u8], pos: &mut usize, n: usize) -> u64 {
        let mut value = 0u64;
        for i in 0..n {
            value |= (data[*pos + i] as u64) << (8 * i);
        }
        *pos += n;
        value
    }

    fn stream0_block_info(data: &[u8]) -> (usize, usize, usize) {
        let cb = data[24] as usize;
        let mut pos = 26;
        let _chunk_size = read_le_n_test(data, &mut pos, cb);
        let chunk_base = pos;
        let _ctype = data[pos];
        pos += 1;
        let _c_len = read_le_n_test(data, &mut pos, cb) as usize;
        let _u_len = read_le_n_test(data, &mut pos, cb);
        let block_offset = resolve_block_offset(
            read_le_n_test(data, &mut pos, cb),
            chunk_base,
            data.len(),
            cb,
        )
        .unwrap();
        let mut bpos = block_offset + 1;
        let c_len = read_le_n_test(data, &mut bpos, cb) as usize;
        (cb, block_offset, c_len)
    }

    fn build_lrzip_with_lzma_props(data: &[u8], props: LzmaProperties) -> Vec<u8> {
        use crate::compress::rzip;
        let dict_size = 4096u32;
        let crc = rzip::legacy_crc32(data);
        let (stream0, stream1) = rzip::encode::encode_chunk(data, crc);
        let s0_compressed = lzma::lzma_encode_with_props(&stream0, dict_size, props);
        let s1_compressed = lzma::lzma_encode_with_props(&stream1, dict_size, props);

        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.push(0);
        output.push(6);
        output.extend_from_slice(&(data.len() as u64).to_le_bytes());
        output.extend_from_slice(&[0u8; 2]);
        output.push(props.to_props_byte());
        output.extend_from_slice(&dict_size.to_le_bytes());
        output.extend_from_slice(&[0u8; 3]);

        let mut chunk_bytes = rzip::encode::compute_chunk_bytes(data.len() as u64) as usize;
        loop {
            let stream_header_size = 1 + 3 * chunk_bytes;
            let block_header_size = 1 + 3 * chunk_bytes;
            let data_start = NUM_STREAMS * stream_header_size;
            let s1_block_offset = data_start + block_header_size + s0_compressed.len();
            let required =
                rzip::encode::compute_chunk_bytes((data.len().max(s1_block_offset)) as u64)
                    as usize;
            if required == chunk_bytes {
                break;
            }
            chunk_bytes = required;
        }

        output.push(chunk_bytes as u8);
        output.push(1);
        rzip::encode::write_le_n(&mut output, data.len() as u64, chunk_bytes);

        let cb = chunk_bytes;
        let stream_header_size = 1 + 3 * cb;
        let block_header_size = 1 + 3 * cb;
        let data_start = NUM_STREAMS * stream_header_size;
        let s0_block_offset = data_start;
        let s1_block_offset = data_start + block_header_size + s0_compressed.len();

        output.push(CTYPE_LZMA);
        rzip::encode::write_le_n(&mut output, 0u64, cb);
        rzip::encode::write_le_n(&mut output, 0u64, cb);
        rzip::encode::write_le_n(&mut output, s0_block_offset as u64, cb);

        output.push(CTYPE_LZMA);
        rzip::encode::write_le_n(&mut output, 0u64, cb);
        rzip::encode::write_le_n(&mut output, 0u64, cb);
        rzip::encode::write_le_n(&mut output, s1_block_offset as u64, cb);

        output.push(CTYPE_LZMA);
        rzip::encode::write_le_n(&mut output, s0_compressed.len() as u64, cb);
        rzip::encode::write_le_n(&mut output, stream0.len() as u64, cb);
        rzip::encode::write_le_n(&mut output, 0u64, cb);
        output.extend_from_slice(&s0_compressed);

        output.push(CTYPE_LZMA);
        rzip::encode::write_le_n(&mut output, s1_compressed.len() as u64, cb);
        rzip::encode::write_le_n(&mut output, stream1.len() as u64, cb);
        rzip::encode::write_le_n(&mut output, 0u64, cb);
        output.extend_from_slice(&s1_compressed);

        output
    }

    fn parse_first_chunk_streams(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cb = data[24] as usize;
        let mut pos = 26;
        let _chunk_size = read_le_n_test(data, &mut pos, cb);
        let chunk_base = pos;
        let mut block_offsets = [0usize; NUM_STREAMS];

        for block_offset in &mut block_offsets {
            pos += 1;
            let _ = read_le_n_test(data, &mut pos, cb);
            let _ = read_le_n_test(data, &mut pos, cb);
            *block_offset = resolve_block_offset(
                read_le_n_test(data, &mut pos, cb),
                chunk_base,
                data.len(),
                cb,
            )
            .unwrap();
        }

        let props = LzmaProperties::from_props_byte(data[16]).unwrap();
        let dict_size = u32::from_le_bytes([data[17], data[18], data[19], data[20]]);
        let mut streams = [Vec::new(), Vec::new()];
        for (index, block_offset) in block_offsets.into_iter().enumerate() {
            let mut bpos = block_offset;
            let ctype = data[bpos];
            bpos += 1;
            let c_len = read_le_n_test(data, &mut bpos, cb) as usize;
            let u_len = read_le_n_test(data, &mut bpos, cb);
            let _ = read_le_n_test(data, &mut bpos, cb);
            let block = &data[bpos..bpos + c_len];
            streams[index] = decompress_block(block, ctype, dict_size, props, u_len).unwrap();
        }
        (streams[0].clone(), streams[1].clone())
    }

    #[test]
    fn test_invalid_magic() {
        let result = decode(&[0x00; 30]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("magic")));
    }

    #[test]
    fn test_input_too_short() {
        let result = decode(b"LRZI");
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
    fn test_roundtrip_repeated() {
        let data = b"The quick brown fox. ".repeat(100);
        let compressed = super::super::encode::encode(&data);
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
    fn test_crc32_verified() {
        let data = b"test data for CRC";
        let mut compressed = super::super::encode::encode(data);
        // Corrupt a byte in the data area (after headers)
        if compressed.len() > 30 {
            let idx = compressed.len() - 5;
            compressed[idx] ^= 0xFF;
        }
        assert!(decode(&compressed).is_err());
    }

    #[test]
    fn test_encrypted_rejected() {
        let mut data = super::super::encode::encode(b"test");
        // Set encrypt flag (byte 22) to 1
        data[22] = 1;
        assert!(matches!(decode(&data), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_unsupported_version() {
        let mut data = super::super::encode::encode(b"test");
        // Set major version to 1 (we only support 0)
        data[4] = 1;
        assert!(matches!(decode(&data), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_invalid_lzma_props_byte() {
        let mut data = super::super::encode::encode(b"test");
        data[16] = 0xE1;
        assert!(
            matches!(decode(&data), Err(Error::InvalidData(msg)) if msg.contains("LZMA properties"))
        );
    }

    #[test]
    fn test_non_default_lzma_props_byte_supported() {
        let props = LzmaProperties {
            lc: 4,
            lp: 0,
            pb: 0,
        };
        let encoded = build_lrzip_with_lzma_props(b"lrzip props test", props);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"lrzip props test");
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let data = b"X";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_invalid_chunk_bytes_zero() {
        let mut data = super::super::encode::encode(b"A");
        // Byte 24 is the first chunk's chunk_bytes field; set to 0 (invalid)
        data[24] = 0;
        assert!(
            matches!(decode(&data), Err(Error::InvalidData(msg)) if msg.contains("chunk_bytes"))
        );
    }

    #[test]
    fn test_invalid_chunk_bytes_too_large() {
        let mut data = super::super::encode::encode(b"A");
        // Set chunk_bytes to 9 (> 8, invalid)
        data[24] = 9;
        assert!(
            matches!(decode(&data), Err(Error::InvalidData(msg)) if msg.contains("chunk_bytes"))
        );
    }

    #[test]
    fn test_size_mismatch() {
        let mut data = super::super::encode::encode(b"test");
        // Corrupt the total_size field (bytes 6-13) to a wrong value
        data[6] = 99;
        assert!(
            matches!(decode(&data), Err(Error::InvalidData(msg)) if msg.contains("size mismatch"))
        );
    }

    #[test]
    fn test_roundtrip_incompressible() {
        // Random-looking data that LZMA cannot compress well -> CTYPE_NONE path
        let data: alloc::vec::Vec<u8> = (0u8..=255)
            .cycle()
            .take(50)
            .enumerate()
            .map(|(i, b)| b.wrapping_mul(i as u8).wrapping_add(37))
            .collect();
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_literal_run_large() {
        let data: alloc::vec::Vec<u8> = (0u64..70_000)
            .map(|i| (i.wrapping_mul(37).wrapping_add(i.wrapping_mul(i))) as u8)
            .collect();
        assert!(data.len() > u16::MAX as usize);
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_medium_repeated() {
        let pattern: alloc::vec::Vec<u8> = (0u16..10_000).map(|i| (i % 251) as u8).collect();
        let filler: alloc::vec::Vec<u8> = (0u16..5_000).map(|i| (i % 197 + 50) as u8).collect();
        let mut data = alloc::vec::Vec::with_capacity(pattern.len() * 2 + filler.len());
        data.extend_from_slice(&pattern);
        data.extend_from_slice(&filler);
        data.extend_from_slice(&pattern);
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_bzip2_backend() {
        use super::super::encode::CompressionType;
        let data = b"Hello bzip2 backend!";
        let compressed = super::super::encode::encode_with(data, CompressionType::Bzip2);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_gzip_backend() {
        use super::super::encode::CompressionType;
        let data = b"Hello gzip backend!";
        let compressed = super::super::encode::encode_with(data, CompressionType::Gzip);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_lzo_backend() {
        use super::super::encode::CompressionType;
        let data = b"Hello LZO backend! ".repeat(10);
        let compressed = super::super::encode::encode_with(&data, CompressionType::Lzo);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_zpaq_backend() {
        use super::super::encode::CompressionType;
        let data = b"Hello ZPAQ backend!";
        let compressed = super::super::encode::encode_with(data, CompressionType::Zpaq);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_none_backend() {
        use super::super::encode::CompressionType;
        let data = b"Hello none backend!";
        let compressed = super::super::encode::encode_with(data, CompressionType::None);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_to_writer_roundtrip() {
        let data = b"streaming lrzip decode ".repeat(128);
        let compressed = super::super::encode::encode(&data);
        let mut decoded = Vec::new();
        decode_to_writer(Cursor::new(compressed), &mut decoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_nonzero_rzip_token_offset_validated() {
        use super::super::encode::CompressionType;
        let mut compressed =
            super::super::encode::encode_with(b"lrzip token head", CompressionType::None);
        let (cb, block_offset, _) = stream0_block_info(&compressed);
        let block_data_start = block_offset + 1 + 3 * cb;
        compressed[block_data_start] = 0x02;
        compressed[block_data_start + 3..block_data_start + 7].fill(0);

        let result = decode(&compressed);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("rzip: match offset out of range"))
            ),
            "expected out-of-range match offset, got {result:?}"
        );
    }

    #[test]
    fn test_rzip_match_offset_zero_rejected() {
        use super::super::encode::CompressionType;

        let mut compressed = super::super::encode::encode_with(&[b'A'; 64], CompressionType::None);
        let (cb, block_offset, c_len) = stream0_block_info(&compressed);
        let block_data_start = block_offset + 1 + 3 * cb;
        let stream0_end = block_data_start + c_len;

        let mut pos = block_data_start;
        let mut found = false;
        while pos + 3 <= stream0_end {
            let head = compressed[pos];
            pos += 1;
            let len = u16::from_le_bytes([compressed[pos], compressed[pos + 1]]) as usize;
            pos += 2;
            if head == 0x00 && len == 0 {
                break;
            }
            if head == 0x01 {
                compressed[pos..pos + 4].fill(0);
                found = true;
                break;
            }
            if head != 0x00 {
                break;
            }
            pos += if head == 0x00 { 0 } else { 4 };
        }
        assert!(found, "expected a match token in stream0");

        let result = decode(&compressed);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("rzip: match offset out of range"))
            ),
            "expected out-of-range offset error, got {result:?}"
        );
    }

    #[test]
    fn test_block_chain_cycle_detected() {
        let mut compressed = super::super::encode::encode(b"");
        let (cb, block_offset, _) = stream0_block_info(&compressed);
        let next_head_pos = block_offset + 1 + 2 * cb;

        for i in 0..cb {
            compressed[next_head_pos + i] = ((block_offset >> (8 * i)) & 0xFF) as u8;
        }

        let result = decode(&compressed);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("lrzip: block chain cycle detected"))
            ),
            "expected cycle detection, got {result:?}"
        );
    }

    #[test]
    fn test_parse_first_chunk_streams_matches_crate_archive() {
        let data = b"hello lrzip repeated ".repeat(64);
        let archive = super::super::encode::encode(&data);
        let (stream0, stream1) = parse_first_chunk_streams(&archive);
        assert!(!stream0.is_empty());
        assert!(!stream1.is_empty());
    }

    #[test]
    fn test_parse_first_chunk_streams_system_repeated_fixture() {
        let archive = [
            0x4c, 0x52, 0x5a, 0x49, 0x00, 0x06, 0x40, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x10,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x27, 0x00,
            0x03, 0x12, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x01, 0x0c, 0x05, 0x15,
            0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0xb6, 0x09, 0xb1, 0x49, 0x03, 0x34, 0x00,
            0x34, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x6c, 0x72, 0x7a, 0x69,
            0x70, 0x20, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x20, 0x72, 0x65,
            0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x6c,
            0x72, 0x7a, 0x69, 0x70, 0x20, 0x72, 0x65, 0x70, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20,
            0xfe, 0xcb, 0x98, 0x58, 0xf9, 0x38, 0x64, 0xae, 0xf3, 0x16, 0x1b, 0xa3, 0x3f, 0x11,
            0x7d, 0xbc,
        ];
        let (stream0, stream1) = parse_first_chunk_streams(&archive);
        assert_eq!(stream1.len(), 52);
        assert!(stream1.starts_with(b"hello lrzip repeated "));
        assert_eq!(
            stream0,
            [
                0x00, 0x15, 0x00, 0x01, 0x0c, 0x05, 0x15, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00,
                0xb6, 0x09, 0xb1, 0x49,
            ]
        );
    }

    #[test]
    fn test_decode_chunk_streams_system_repeated_fixture() {
        let stream0 = [
            0x00, 0x15, 0x00, 0x01, 0x0c, 0x05, 0x15, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00,
            0xb6, 0x09, 0xb1, 0x49,
        ];
        let stream1 = b"hello lrzip repeated  repeated hello lrzip repeated ".to_vec();
        let mut decoded = Vec::new();
        decode_chunk_streams(&stream0, &stream1, 2, &mut decoded).unwrap();
        assert_eq!(decoded, b"hello lrzip repeated ".repeat(64));
    }

    /// Build an lrzip archive with `md5_flag` set to 1 and the correct MD5
    /// digest of `plaintext` appended after the last chunk.
    fn build_lrzip_with_md5(plaintext: &[u8]) -> Vec<u8> {
        use super::super::encode;
        let mut archive = encode::encode(plaintext);
        // Patch byte 21 to set the MD5 flag.
        archive[21] = 1;
        // Compute MD5 over the expected decoded plaintext and append it.
        let digest = crate::util::md5::md5(plaintext);
        archive.extend_from_slice(&digest);
        archive
    }

    #[test]
    fn test_decode_md5_flag_valid() {
        let plaintext = b"Hello, MD5 verified lrzip!";
        let archive = build_lrzip_with_md5(plaintext);
        let result = decode(&archive).expect("decode with valid MD5 should succeed");
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_decode_md5_flag_mismatch() {
        let plaintext = b"Hello, MD5 verified lrzip!";
        let mut archive = build_lrzip_with_md5(plaintext);
        // Corrupt the appended MD5 digest.
        let len = archive.len();
        archive[len - 1] ^= 0xFF;
        let result = decode(&archive);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("lrzip: MD5 checksum mismatch"))
            ),
            "expected MD5 mismatch error, got {result:?}"
        );
    }

    #[test]
    fn test_decode_md5_flag_truncated() {
        use super::super::encode;
        let plaintext = b"Hello, MD5 lrzip!";
        let mut archive = encode::encode(plaintext);
        archive[21] = 1;
        // Do not append the 16-byte digest — input is too short.
        let result = decode(&archive);
        assert!(
            matches!(result, Err(Error::UnexpectedEof)),
            "expected UnexpectedEof, got {result:?}"
        );
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }
}
