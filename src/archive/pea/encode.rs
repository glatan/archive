//! PEA 1.x archive encoding.
//!
//! Emits the single-stream layout produced by PeaZip's `pea`
//! backend (reference source `pea.pas`/`pea_utils.pas`, snapshots
//! in `docs/spec/sources/`): a 10-byte archive header, one `POD`
//! stream header, the object sequence, an `EOA` trigger, and the
//! stream and volume integrity tags. All multi-byte integer fields
//! are little-endian.
//!
//! File data uses PCOMPRESS0 (stored) or PCOMPRESS2 (zlib deflate
//! over independent 1 MiB blocks, the reference level-6 scheme;
//! blocks that would grow are written raw, as the reference writer
//! does). Integrity tags are emitted for the algorithms this crate
//! implements (`Adler32`, `Crc32`, `Crc64`, `Md5`, `Sha1`,
//! `Sha256`) or omitted with [`PeaAlgo::None`](crate::archive::pea::decode::PeaAlgo::None). Authenticated-
//! encryption streams, multi-stream (`EOS`/`POD`) generation, and
//! multi-volume spanning are intentionally out of scope.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::compress::zlib;
use crate::error::Error;

use super::decode::{FA_DIRECTORY, MAGIC, PeaAlgo, PeaEntry, REV, VER, WBUFSIZE};

/// File-data compression scheme written to the stream header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeaCompression {
    /// PCOMPRESS0: file data is stored uncompressed.
    Store,
    /// PCOMPRESS2: zlib deflate over independent 1 MiB blocks
    /// (the reference level-6 scheme). PCOMPRESS1/3 differ only in
    /// deflate level, which this crate's encoder does not expose.
    #[default]
    Deflate,
}

impl PeaCompression {
    fn code(self) -> u8 {
        match self {
            PeaCompression::Store => 0,
            PeaCompression::Deflate => 2,
        }
    }
}

/// Per-object metadata stored in the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeaEntryOptions {
    /// DOS-format last-modification timestamp, stored raw.
    pub mtime: u32,
    /// Platform attribute word, stored raw. The directory bit
    /// (`0x10`) is forced from the entry kind by the encoder.
    pub attributes: u32,
}

#[derive(Debug)]
struct PendingEntry {
    name: String,
    is_dir: bool,
    mtime: u32,
    attributes: u32,
    data: Vec<u8>,
}

/// Builder for creating PEA archives (single stream).
#[derive(Debug)]
pub struct PeaEncoder {
    entries: Vec<PendingEntry>,
    compression: PeaCompression,
    stream_algo: PeaAlgo,
    obj_algo: PeaAlgo,
    volume_algo: PeaAlgo,
}

impl PeaEncoder {
    /// New encoder: PCOMPRESS2 deflate file data, CRC-32 object,
    /// stream, and volume tags.
    pub fn new() -> Self {
        PeaEncoder {
            entries: Vec::new(),
            compression: PeaCompression::Deflate,
            stream_algo: PeaAlgo::Crc32,
            obj_algo: PeaAlgo::Crc32,
            volume_algo: PeaAlgo::Crc32,
        }
    }

    /// Select the file-data compression scheme.
    pub fn compression(mut self, c: PeaCompression) -> Self {
        self.compression = c;
        self
    }

    /// Select the stream-level control algorithm. Must be
    /// [`PeaAlgo::None`] or an algorithm this crate implements,
    /// checked in [`PeaEncoder::finish`].
    pub fn stream_control(mut self, algo: PeaAlgo) -> Self {
        self.stream_algo = algo;
        self
    }

    /// Select the per-object control algorithm; same constraint as
    /// [`PeaEncoder::stream_control`].
    pub fn object_control(mut self, algo: PeaAlgo) -> Self {
        self.obj_algo = algo;
        self
    }

    /// Select the volume-level control algorithm; same constraint
    /// as [`PeaEncoder::stream_control`].
    pub fn volume_control(mut self, algo: PeaAlgo) -> Self {
        self.volume_algo = algo;
        self
    }

    /// Add a regular file entry with default metadata.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_with_options(name, data, &PeaEntryOptions::default());
    }

    /// Add a regular file entry with explicit metadata.
    pub fn add_file_with_options(&mut self, name: &str, data: &[u8], options: &PeaEntryOptions) {
        self.entries.push(PendingEntry {
            name: name.to_string(),
            is_dir: false,
            mtime: options.mtime,
            attributes: options.attributes,
            data: data.to_vec(),
        });
    }

    /// Add a directory entry with default metadata.
    pub fn add_dir(&mut self, name: &str) {
        self.add_dir_with_options(name, &PeaEntryOptions::default());
    }

    /// Add a directory entry with explicit metadata.
    pub fn add_dir_with_options(&mut self, name: &str, options: &PeaEntryOptions) {
        self.entries.push(PendingEntry {
            name: name.to_string(),
            is_dir: true,
            mtime: options.mtime,
            attributes: options.attributes,
            data: Vec::new(),
        });
    }

    /// Add an entry previously decoded from another archive,
    /// preserving its name, kind, timestamp, and attributes.
    pub fn add_entry(&mut self, entry: &PeaEntry) {
        self.entries.push(PendingEntry {
            name: entry.name.clone(),
            is_dir: entry.is_dir,
            mtime: entry.mtime,
            attributes: entry.attributes,
            data: if entry.is_dir {
                Vec::new()
            } else {
                entry.data.clone()
            },
        });
    }

    /// Finish the archive and return its serialized bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        for algo in [self.volume_algo, self.stream_algo, self.obj_algo] {
            check_algo(algo)?;
        }
        for e in &self.entries {
            check_name(&e.name)?;
        }

        let mut out = Vec::new();
        // archive header: magic, ver/rev, volume control, ECC=0,
        // OS=1, datetime-encoding=1, ANSI=1, little-endian x86=0,
        // niter=0 (see `pea_archive_hdr`)
        out.extend_from_slice(&[MAGIC, VER, REV, self.volume_algo.code(), 0, 1, 1, 1, 0, 0]);
        // stream header: POD trigger, compression, ECC=0, stream
        // and object control algorithms (see `pea_stream_hdr`)
        out.extend_from_slice(&[
            0,
            0,
            b'P',
            b'O',
            b'D',
            0,
            self.compression.code(),
            0,
            self.stream_algo.code(),
            self.obj_algo.code(),
        ]);
        for e in &self.entries {
            write_object(&mut out, e, self.compression, self.obj_algo);
        }
        // EOA trigger ends the archive's single stream
        out.extend_from_slice(&[0, 0, b'E', b'O', b'A', 0]);
        // stream tag covers everything from the archive start
        // through the EOA trigger; the volume tag covers all
        // preceding bytes including the stream tag
        push_tag(&mut out, self.stream_algo);
        push_tag(&mut out, self.volume_algo);
        Ok(out)
    }
}

impl Default for PeaEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode `entries` as a PEA archive with default settings
/// (PCOMPRESS2 deflate, CRC-32 object/stream/volume tags).
pub fn encode(entries: &[PeaEntry]) -> Result<Vec<u8>, Error> {
    let mut enc = PeaEncoder::new();
    for e in entries {
        enc.add_entry(e);
    }
    enc.finish()
}

fn check_algo(algo: PeaAlgo) -> Result<(), Error> {
    if algo == PeaAlgo::None || algo.compute(&[]).is_some() {
        Ok(())
    } else {
        Err(Error::Unsupported("pea control algorithm"))
    }
}

fn check_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidData("pea: empty object name"));
    }
    if name.len() > u16::MAX as usize {
        return Err(Error::InvalidData("pea: object name too long"));
    }
    if name.as_bytes().contains(&0) {
        return Err(Error::InvalidData("pea: NUL in object name"));
    }
    Ok(())
}

/// Append the integrity tag of `algo` over every byte emitted so
/// far (stream/volume coverage); a no-op for [`PeaAlgo::None`].
fn push_tag(out: &mut Vec<u8>, algo: PeaAlgo) {
    if let Some(tag) = algo.compute(out) {
        out.extend_from_slice(&tag);
    }
}

fn write_object(
    out: &mut Vec<u8>,
    e: &PendingEntry,
    compression: PeaCompression,
    obj_algo: PeaAlgo,
) {
    let attributes = if e.is_dir {
        e.attributes | FA_DIRECTORY
    } else {
        e.attributes & !FA_DIRECTORY
    };
    let name_len = e.name.len() as u16;
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(e.name.as_bytes());
    out.extend_from_slice(&e.mtime.to_le_bytes());
    out.extend_from_slice(&attributes.to_le_bytes());
    // object tag coverage: header fields (+ file size for files),
    // then the object data as fed by the reference writer
    let mut covered = Vec::with_capacity(e.name.len() + 18);
    covered.extend_from_slice(&name_len.to_le_bytes());
    covered.extend_from_slice(e.name.as_bytes());
    covered.extend_from_slice(&e.mtime.to_le_bytes());
    covered.extend_from_slice(&attributes.to_le_bytes());
    if !e.is_dir {
        let file_size = e.data.len() as u64;
        out.extend_from_slice(&file_size.to_le_bytes());
        covered.extend_from_slice(&file_size.to_le_bytes());
        if !e.data.is_empty() {
            match compression {
                PeaCompression::Store => {
                    out.extend_from_slice(&e.data);
                    covered.extend_from_slice(&e.data);
                }
                PeaCompression::Deflate => write_compressed(out, &mut covered, &e.data),
            }
        }
    }
    if let Some(tag) = obj_algo.compute(&covered) {
        out.extend_from_slice(&tag);
    }
}

/// PCOMPRESS1-3 file-data area: `[u32 compsize][zlib block]` per
/// 1 MiB input chunk, then a u32 with the uncompressed size of the
/// last block. A block whose compressed form does not shrink is
/// written raw with `compsize` equal to the input size, mirroring
/// `compress_file` in the reference implementation. The object tag
/// covers `compsize` plus the *uncompressed* block data.
fn write_compressed(out: &mut Vec<u8>, covered: &mut Vec<u8>, data: &[u8]) {
    let mut last_out = 0u32;
    for chunk in data.chunks(WBUFSIZE) {
        let comp = zlib::encode::encode(chunk);
        let (compsize, block) = if comp.len() >= chunk.len() {
            (chunk.len() as u32, chunk)
        } else {
            (comp.len() as u32, &comp[..])
        };
        out.extend_from_slice(&compsize.to_le_bytes());
        out.extend_from_slice(block);
        covered.extend_from_slice(&compsize.to_le_bytes());
        covered.extend_from_slice(chunk);
        last_out = chunk.len() as u32;
    }
    out.extend_from_slice(&last_out.to_le_bytes());
    covered.extend_from_slice(&last_out.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::pea::decode;

    fn xorshift_bytes(n: usize) -> Vec<u8> {
        let mut s = 0x1234_5678u32;
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                s as u8
            })
            .collect()
    }

    #[test]
    fn pea_encode_roundtrip() {
        let mut enc = PeaEncoder::new().compression(PeaCompression::Store);
        enc.add_dir("dir");
        enc.add_file("dir/file.txt", b"hello pea");
        enc.add_file("empty.bin", b"");
        let f = enc.finish().unwrap();
        assert_eq!(&f[..4], &[0xEA, 1, 6, 2]);
        let img = decode::decode(&f).unwrap();
        assert_eq!(img.version, (1, 6));
        assert_eq!(img.entries.len(), 3);
        assert!(img.entries[0].is_dir);
        assert_eq!(img.entries[1].name, "dir/file.txt");
        assert_eq!(img.entries[1].data, b"hello pea");
        assert!(!img.entries[2].is_dir);
        assert!(img.entries[2].data.is_empty());
    }

    #[test]
    fn pea_encode_compressed_roundtrip() {
        let mut enc = PeaEncoder::new();
        enc.add_file("f.bin", b"compress me compress me compress me");
        let f = enc.finish().unwrap();
        // stream header declares PCOMPRESS2
        assert_eq!(f[16], 2);
        let img = decode::decode(&f).unwrap();
        assert_eq!(img.entries[0].name, "f.bin");
        assert_eq!(img.entries[0].data, b"compress me compress me compress me");
    }

    #[test]
    fn pea_encode_compressed_multiblock() {
        // > 1 MiB so the file-data area spans several blocks plus a
        // short tail block
        let data: Vec<u8> = (0..(WBUFSIZE + 12345))
            .map(|i| b'a' + (i / 65536 % 26) as u8)
            .collect();
        let mut enc = PeaEncoder::new();
        enc.add_file("big.bin", &data);
        let f = enc.finish().unwrap();
        assert!(f.len() < data.len());
        let img = decode::decode(&f).unwrap();
        assert_eq!(img.entries[0].data, data);
    }

    #[test]
    fn pea_encode_raw_block_fallback() {
        // incompressible data triggers the stored-block fallback
        // (compsize == uncompressed block size on the wire)
        let data = xorshift_bytes(8192);
        let mut enc = PeaEncoder::new();
        enc.add_file("rand.bin", &data);
        let f = enc.finish().unwrap();
        assert!(f.windows(data.len()).any(|w| w == data.as_slice()));
        let img = decode::decode(&f).unwrap();
        assert_eq!(img.entries[0].data, data);
    }

    #[test]
    fn pea_encode_rejects_bad_name() {
        let mut enc = PeaEncoder::new();
        enc.add_file("", b"x");
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));

        let mut enc = PeaEncoder::new();
        enc.add_file("bad\0name", b"x");
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));

        let mut enc = PeaEncoder::new();
        enc.add_file(&"n".repeat(u16::MAX as usize + 1), b"x");
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn pea_encode_rejects_unsupported_algo() {
        // algorithms the crate parses but cannot compute are
        // rejected, as are authenticated-encryption schemes
        for algo in [PeaAlgo::Sha512, PeaAlgo::Blake2b, PeaAlgo::Encrypted(49)] {
            let mut enc = PeaEncoder::new().object_control(algo);
            enc.add_file("a", b"x");
            assert!(matches!(enc.finish(), Err(Error::Unsupported(_))));
        }
        let mut enc = PeaEncoder::new().stream_control(PeaAlgo::Whirlpool);
        enc.add_file("a", b"x");
        assert!(matches!(enc.finish(), Err(Error::Unsupported(_))));
        let mut enc = PeaEncoder::new().volume_control(PeaAlgo::Ripemd160);
        enc.add_file("a", b"x");
        assert!(matches!(enc.finish(), Err(Error::Unsupported(_))));
    }

    #[test]
    fn pea_encode_control_algo_selection() {
        let mut enc = PeaEncoder::new()
            .object_control(PeaAlgo::Sha256)
            .stream_control(PeaAlgo::Sha1)
            .volume_control(PeaAlgo::Md5);
        enc.add_dir("d");
        enc.add_file("d/f", b"tagged with strong hashes");
        let img = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(img.entries.len(), 2);
        assert_eq!(img.entries[1].data, b"tagged with strong hashes");

        // no tags at all
        let mut enc = PeaEncoder::new()
            .object_control(PeaAlgo::None)
            .stream_control(PeaAlgo::None)
            .volume_control(PeaAlgo::None);
        enc.add_file("a", b"x");
        let img = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(img.entries[0].data, b"x");
    }

    #[test]
    fn pea_encode_add_entry_preserves_metadata() {
        let opts = PeaEntryOptions {
            mtime: 0x5432,
            attributes: 0x20,
        };
        let mut enc = PeaEncoder::new();
        enc.add_file_with_options("meta.bin", b"m", &opts);
        let img = decode::decode(&enc.finish().unwrap()).unwrap();
        let mut enc = PeaEncoder::new();
        enc.add_entry(&img.entries[0]);
        let img = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(img.entries[0].mtime, 0x5432);
        assert_eq!(img.entries[0].attributes, 0x20);
        assert_eq!(img.entries[0].data, b"m");
    }

    #[test]
    fn pea_encode_helper() {
        let entries = [PeaEntry {
            name: String::from("one.txt"),
            is_dir: false,
            mtime: 0,
            attributes: 0,
            data: b"1".to_vec(),
        }];
        let img = decode::decode(&encode(&entries).unwrap()).unwrap();
        assert_eq!(img.entries[0].name, "one.txt");
        assert_eq!(img.entries[0].data, b"1");
    }
}
