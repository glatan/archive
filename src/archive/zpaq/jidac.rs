//! Upstream zpaq JIDAC journaling format (the `zpaq add`/`zpaq x`
//! append-only archive layout).
//!
//! A JIDAC archive is a sequence of single-segment ZPAQ blocks whose
//! segments carry filenames `jDC<fdate14><type><num10>` and comments
//! `<usize> jDC\x01`, where `fdate` is `yyyymmddhhmmss`, `type` is
//! `c` (transaction header), `d` (data fragments), `h` (fragment
//! table), or `i` (index), and `usize` is the uncompressed payload
//! size. Each transaction is `c` then `d` then `h` then `i` blocks:
//!
//! - `c`: 8-byte `jmp` — byte size of the transaction's `d` blocks;
//!   negative marks an incomplete transaction. `num` = total
//!   fragments stored so far.
//! - `d`: concatenated fragment data followed by `usize[4] * frags`,
//!   `0[4]`, `frags[4]`; `num` = first fragment id.
//! - `h`: `bsize[4]` (compressed size of the matching `d` block)
//!   followed by `sha1[20] usize[4]` per fragment; `num` = first
//!   fragment id.
//! - `i`: per entry `date[8] filename 0 na[4] attr[na] ni[4]
//!   ptr[ni][4]` for additions or `0[8] filename 0` for deletions.
//!   `ptr` entries are fragment ids.
//!
//! Fragments are global across transactions: later transactions reuse
//! earlier fragment ids for deduplication. Fragment id 0 is reserved
//! (upstream `ht.resize(1)`); real fragments start at 1. The latest
//! view applies all `i` blocks in order; deletion entries remove the
//! filename.
//!
//! This module provides read support ([`decode_jidac`]) and
//! single-transaction write support ([`encode_jidac`]); fragment
//! deduplication on write is out of scope — each stored entry becomes
//! one fragment.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::compress::zpaq::decode::{BlockDecoder, parse_block_header_at};
use crate::compress::zpaq::encode::BlockEncoder;
use crate::compress::zpaq::models;
use crate::error::Error;
use crate::util::sha1::sha1;

const JIDAC_SUFFIX: &[u8] = b"jDC\x01";

/// One file recovered from a JIDAC archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JidacFile {
    /// Raw filename bytes.
    pub filename: Vec<u8>,
    /// `yyyymmddhhmmss` timestamp, or 0 if the index recorded none.
    pub date: i64,
    /// Packed attributes (`attr << 8 | 'u'` unix / `'w'` windows), or 0.
    pub attr: u64,
    /// Reconstructed file contents (fragment pointers resolved).
    pub data: Vec<u8>,
}

/// One committed transaction's view: the files visible after its
/// `i` blocks were applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JidacVersion {
    /// `yyyymmddhhmmss` transaction date from the `c` block filename.
    pub date: i64,
    /// Files visible at the end of this transaction.
    pub files: Vec<JidacFile>,
}

/// A decoded JIDAC archive: committed versions plus the latest view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JidacJournal {
    /// Committed transactions in stream order.
    pub versions: Vec<JidacVersion>,
    /// Files visible after all committed transactions.
    pub files: Vec<JidacFile>,
}

struct FileRecord {
    date: i64,
    attr: u64,
    ptrs: Vec<u32>,
}

fn btoi(b: &[u8]) -> Result<u32, Error> {
    if b.len() < 4 {
        return Err(Error::InvalidData("zpaq jidac: truncated field"));
    }
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn btol(b: &[u8]) -> Result<i64, Error> {
    if b.len() < 8 {
        return Err(Error::InvalidData("zpaq jidac: truncated field"));
    }
    Ok(i64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Parse `<usize> ...jDC\x01` from a segment comment.
fn parse_comment(comment: &[u8]) -> Option<u64> {
    if comment.len() < JIDAC_SUFFIX.len() || !comment.ends_with(JIDAC_SUFFIX) {
        return None;
    }
    let mut usize_: u64 = 0;
    for &c in comment {
        if !c.is_ascii_digit() {
            break;
        }
        usize_ = usize_.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
        if usize_ > 0xFFFF_FFFF {
            return None;
        }
    }
    Some(usize_)
}

/// Parse `jDC<fdate14><type><num10>`; returns (fdate, type, num).
fn parse_filename(filename: &[u8]) -> Result<(i64, u8, u32), Error> {
    if filename.len() != 28 || !filename.starts_with(b"jDC") {
        return Err(Error::InvalidData("zpaq jidac: bad block name"));
    }
    let digits = |lo: usize, hi: usize| -> Result<i64, Error> {
        let mut v: i64 = 0;
        for &c in &filename[lo..hi] {
            if !c.is_ascii_digit() {
                return Err(Error::InvalidData("zpaq jidac: bad block name"));
            }
            v = v * 10 + i64::from(c - b'0');
        }
        Ok(v)
    };
    let fdate = digits(3, 17)?;
    if !(19_000_000_000_000..30_000_000_000_000).contains(&fdate) {
        return Err(Error::InvalidData("zpaq jidac: bad date"));
    }
    let num = digits(18, 28)?;
    if num > 0xFFFF_FFFF {
        return Err(Error::InvalidData("zpaq jidac: bad fragment"));
    }
    Ok((fdate, filename[17], num as u32))
}

fn snapshot(
    dt: &BTreeMap<Vec<u8>, FileRecord>,
    frags: &[Vec<u8>],
) -> Result<Vec<JidacFile>, Error> {
    let mut files = Vec::with_capacity(dt.len());
    for (filename, rec) in dt {
        let mut data = Vec::new();
        for &p in &rec.ptrs {
            let frag = frags
                .get(p as usize)
                .ok_or(Error::InvalidData("zpaq jidac: missing fragment"))?;
            data.extend_from_slice(frag);
        }
        files.push(JidacFile {
            filename: filename.clone(),
            date: rec.date,
            attr: rec.attr,
            data,
        });
    }
    Ok(files)
}

/// Decode an upstream JIDAC journaling archive.
///
/// Returns the committed versions and the latest file view. Streams
/// that mix JIDAC and plain segments, contain malformed JIDAC
/// metadata, or reference missing fragments are rejected. A trailing
/// incomplete transaction (`jmp < 0`) is ignored like upstream does.
pub fn decode_jidac(input: &[u8]) -> Result<JidacJournal, Error> {
    let mut frags: Vec<Vec<u8>> = Vec::new();
    let mut dt: BTreeMap<Vec<u8>, FileRecord> = BTreeMap::new();
    let mut versions: Vec<JidacVersion> = Vec::new();
    let mut saw_jidac = false;
    let mut incomplete = false;

    let mut start = 0;
    while !incomplete {
        let Some(header) = parse_block_header_at(input, start)? else {
            break;
        };
        let mut block = BlockDecoder::new(input, &header, usize::MAX)?;
        while let Some(segment) = block.next_segment()? {
            let Some(usize_field) = parse_comment(&segment.comment) else {
                if saw_jidac {
                    return Err(Error::InvalidData(
                        "zpaq jidac: mixed journaling and streaming blocks",
                    ));
                }
                return Err(Error::InvalidData("zpaq jidac: not a journaling archive"));
            };
            saw_jidac = true;
            let (fdate, ftype, num) = parse_filename(&segment.filename)?;
            let payload = &segment.data;
            match ftype {
                b'c' => {
                    if payload.len() != usize_field as usize || payload.len() < 8 {
                        return Err(Error::InvalidData("zpaq jidac: bad c block size"));
                    }
                    let jmp = btol(payload)?;
                    if jmp < 0 {
                        incomplete = true;
                        break;
                    }
                    versions.push(JidacVersion {
                        date: fdate,
                        files: Vec::new(),
                    });
                }
                b'd' => {
                    // payload = fragdata + usize[4]*n + 0[4] + n[4]
                    if payload.len() < 8 {
                        return Err(Error::InvalidData("zpaq jidac: bad d block size"));
                    }
                    let n = btoi(&payload[payload.len() - 4..])? as usize;
                    let trailer = 8 + n
                        .checked_mul(4)
                        .ok_or(Error::InvalidData("zpaq jidac: d block too large"))?;
                    if payload.len() < trailer {
                        return Err(Error::InvalidData("zpaq jidac: bad d block size"));
                    }
                    let sizes_start = payload.len() - trailer;
                    let mut sizes = Vec::with_capacity(n);
                    let mut total = 0usize;
                    for i in 0..n {
                        let s = btoi(&payload[sizes_start + i * 4..])? as usize;
                        total = total
                            .checked_add(s)
                            .ok_or(Error::InvalidData("zpaq jidac: d block too large"))?;
                        sizes.push(s);
                    }
                    if total > sizes_start {
                        return Err(Error::InvalidData("zpaq jidac: d block too large"));
                    }
                    if (num as usize) < frags.len() {
                        return Err(Error::InvalidData("zpaq jidac: unordered fragments"));
                    }
                    while frags.len() < num as usize {
                        frags.push(Vec::new());
                    }
                    let mut off = 0usize;
                    for s in sizes {
                        frags.push(payload[off..off + s].to_vec());
                        off += s;
                    }
                }
                b'h' => {
                    if payload.len() != usize_field as usize
                        || payload.len() < 4
                        || (payload.len() - 4) % 24 != 0
                    {
                        return Err(Error::InvalidData("zpaq jidac: bad h block size"));
                    }
                    let n = (payload.len() - 4) / 24;
                    // Verify recorded sizes against stored fragments.
                    let mut s = 4usize;
                    for i in 0..n {
                        let id = num as usize + i;
                        let recorded = btoi(&payload[s + 20..s + 24])? as usize;
                        match frags.get(id) {
                            Some(frag) if frag.len() == recorded => {}
                            Some(_) => {
                                return Err(Error::InvalidData(
                                    "zpaq jidac: fragment size mismatch",
                                ));
                            }
                            None => {
                                return Err(Error::InvalidData(
                                    "zpaq jidac: fragment table without data",
                                ));
                            }
                        }
                        s += 24;
                    }
                }
                b'i' => {
                    if payload.len() != usize_field as usize {
                        return Err(Error::InvalidData("zpaq jidac: bad i block size"));
                    }
                    let mut s = 0usize;
                    while s + 9 <= payload.len() {
                        let date = btol(&payload[s..])?;
                        s += 8;
                        let name_start = s;
                        while s < payload.len() && payload[s] != 0 {
                            s += 1;
                        }
                        if s >= payload.len() {
                            return Err(Error::InvalidData("zpaq jidac: bad i entry"));
                        }
                        let filename = payload[name_start..s].to_vec();
                        s += 1;
                        if date == 0 {
                            dt.remove(&filename);
                            continue;
                        }
                        if s + 4 > payload.len() {
                            return Err(Error::InvalidData("zpaq jidac: missing attr"));
                        }
                        let na = btoi(&payload[s..])? as usize;
                        s += 4;
                        if s + na > payload.len() || na > 65535 {
                            return Err(Error::InvalidData("zpaq jidac: attr too long"));
                        }
                        let mut attr = 0u64;
                        for (i, &b) in payload[s..s + na].iter().take(8).enumerate() {
                            attr += u64::from(b) << (i * 8);
                        }
                        s += na;
                        if s + 4 > payload.len() {
                            return Err(Error::InvalidData("zpaq jidac: missing ptr"));
                        }
                        let ni = btoi(&payload[s..])? as usize;
                        s += 4;
                        if s + ni * 4 > payload.len() {
                            return Err(Error::InvalidData("zpaq jidac: ptr list too long"));
                        }
                        let mut ptrs = Vec::with_capacity(ni);
                        for _ in 0..ni {
                            ptrs.push(btoi(&payload[s..])?);
                            s += 4;
                        }
                        dt.insert(filename, FileRecord { date, attr, ptrs });
                    }
                    if s != payload.len() {
                        return Err(Error::InvalidData("zpaq jidac: bad i block size"));
                    }
                    if let Some(v) = versions.last_mut() {
                        v.files = snapshot(&dt, &frags)?;
                    }
                }
                _ => {
                    return Err(Error::InvalidData("zpaq jidac: unexpected block type"));
                }
            }
        }
        start = block.end_pos();
    }
    if start == 0 {
        return Err(Error::InvalidData("zpaq: no block locator found"));
    }
    if !saw_jidac {
        return Err(Error::InvalidData("zpaq jidac: not a journaling archive"));
    }
    let files = snapshot(&dt, &frags)?;
    Ok(JidacJournal { versions, files })
}

/// One file to store in a JIDAC transaction.
#[derive(Debug, Clone)]
pub struct JidacInput<'a> {
    /// Raw filename bytes (must not contain NUL).
    pub filename: &'a [u8],
    /// `yyyymmddhhmmss` timestamp; 0 is replaced by the transaction
    /// `date` (an `i`-block date of 0 marks a deletion upstream).
    pub date: i64,
    /// Packed attributes, or 0 for none.
    pub attr: u64,
    /// File contents; stored as one fragment.
    pub data: &'a [u8],
}

fn jidac_name(date: i64, ftype: u8, num: u32) -> Result<Vec<u8>, Error> {
    if !(19_000_000_000_000..30_000_000_000_000).contains(&date) {
        return Err(Error::InvalidData("zpaq jidac: bad date"));
    }
    let mut name = Vec::with_capacity(28);
    name.extend_from_slice(b"jDC");
    name.extend_from_slice(alloc::format!("{date:014}").as_bytes());
    name.push(ftype);
    name.extend_from_slice(alloc::format!("{num:010}").as_bytes());
    Ok(name)
}

fn jidac_comment(usize_: usize) -> Vec<u8> {
    let mut c = Vec::with_capacity(16);
    c.extend_from_slice(alloc::format!("{usize_}").as_bytes());
    c.extend_from_slice(JIDAC_SUFFIX);
    c
}

fn block_encoder(level: u8) -> Result<BlockEncoder, Error> {
    BlockEncoder::new(models::model_zpaql(u32::from(level))?, level)
}

fn emit_block(
    out: &mut Vec<u8>,
    level: u8,
    name: &[u8],
    comment: &[u8],
    data: &[u8],
) -> Result<(), Error> {
    let mut block = block_encoder(level)?;
    block.write_block_header(out);
    block.encode_segment(out, name, comment, data)?;
    out.push(255);
    Ok(())
}

/// Encode a single-transaction JIDAC archive that upstream `zpaq x`
/// and `zpaq l` can read.
///
/// Each entry becomes one fragment (no deduplication); the archive
/// contains exactly one `c`/`d`/`h`/`i` transaction. `level` selects
/// the compression model (`1..=3` for the built-in models, `2` for
/// unmodeled storage via [`crate::compress::zpaq::encode::encode`]
/// semantics — all produced blocks are modeled at `level`).
pub fn encode_jidac(entries: &[JidacInput], date: i64, level: u8) -> Result<Vec<u8>, Error> {
    if !(1..=3).contains(&level) {
        return Err(Error::InvalidData("zpaq jidac: level must be 1..=3"));
    }
    for e in entries {
        if e.filename.contains(&0) {
            return Err(Error::InvalidData("zpaq jidac: NUL in filename"));
        }
        if e.data.len() > 0x7FFF_FFFF {
            return Err(Error::InvalidData("zpaq jidac: fragment too big"));
        }
    }

    // Build the d block first so its compressed size fills the c
    // block's jmp field and the h block's bsize field.
    let mut dpayload = Vec::new();
    let mut sizes = Vec::with_capacity(entries.len());
    for e in entries {
        dpayload.extend_from_slice(e.data);
        sizes.push(e.data.len() as u32);
    }
    for &s in &sizes {
        dpayload.extend_from_slice(&s.to_le_bytes());
    }
    dpayload.extend_from_slice(&0u32.to_le_bytes());
    dpayload.extend_from_slice(&(sizes.len() as u32).to_le_bytes());

    let mut dblock = Vec::new();
    emit_block(
        &mut dblock,
        level,
        &jidac_name(date, b'd', 1)?,
        &jidac_comment(dpayload.len()),
        &dpayload,
    )?;

    let mut out = Vec::new();
    // c block: jmp = compressed byte size of the d block; num =
    // htsize = 1 (upstream reserves fragment 0).
    emit_block(
        &mut out,
        level,
        &jidac_name(date, b'c', 1)?,
        &jidac_comment(8),
        &(dblock.len() as i64).to_le_bytes(),
    )?;
    out.extend_from_slice(&dblock);

    // h block: bsize + sha1[20] usize[4] per fragment.
    let mut hpayload = Vec::new();
    hpayload.extend_from_slice(&(dblock.len() as u32).to_le_bytes());
    for e in entries {
        hpayload.extend_from_slice(&sha1(e.data));
        hpayload.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
    }
    emit_block(
        &mut out,
        level,
        &jidac_name(date, b'h', 1)?,
        &jidac_comment(hpayload.len()),
        &hpayload,
    )?;

    // i block: one add entry per file.
    let mut ipayload = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let fdate = if e.date == 0 { date } else { e.date };
        ipayload.extend_from_slice(&fdate.to_le_bytes());
        ipayload.extend_from_slice(e.filename);
        ipayload.push(0);
        if e.attr == 0 {
            ipayload.extend_from_slice(&0u32.to_le_bytes());
        } else if (e.attr & 0xFF) == u64::from(b'u') {
            ipayload.extend_from_slice(&3u32.to_le_bytes());
            ipayload.extend_from_slice(&(e.attr as u32).to_le_bytes()[..3]);
        } else if (e.attr & 0xFF) == u64::from(b'w') {
            ipayload.extend_from_slice(&5u32.to_le_bytes());
            ipayload.extend_from_slice(&(e.attr as u32).to_le_bytes()[..4]);
            ipayload.push((e.attr >> 32) as u8);
        } else {
            ipayload.extend_from_slice(&0u32.to_le_bytes());
        }
        ipayload.extend_from_slice(&1u32.to_le_bytes());
        ipayload.extend_from_slice(&(i as u32 + 1).to_le_bytes());
    }
    emit_block(
        &mut out,
        level,
        &jidac_name(date, b'i', 1)?,
        &jidac_comment(ipayload.len()),
        &ipayload,
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(name: &'a str, data: &'a [u8]) -> JidacInput<'a> {
        JidacInput {
            filename: name.as_bytes(),
            date: 20_250_101_120_000,
            attr: 0,
            data,
        }
    }

    #[test]
    fn jidac_single_file_roundtrip() {
        let data = b"journal payload";
        let enc = encode_jidac(&[entry("a.txt", data)], 20_250_101_120_000, 2).unwrap();
        let j = decode_jidac(&enc).unwrap();
        assert_eq!(j.versions.len(), 1);
        assert_eq!(j.files.len(), 1);
        assert_eq!(j.files[0].filename, b"a.txt");
        assert_eq!(j.files[0].data, data);
        assert_eq!(j.versions[0].files, j.files);
    }

    #[test]
    fn jidac_multi_file_roundtrip() {
        let enc = encode_jidac(
            &[
                entry("x/one.bin", b"first"),
                entry("two.bin", &[0u8; 1024]),
                JidacInput {
                    filename: b"empty",
                    date: 20_250_101_120_000,
                    attr: 0,
                    data: b"",
                },
            ],
            20_250_101_120_000,
            1,
        )
        .unwrap();
        let j = decode_jidac(&enc).unwrap();
        assert_eq!(j.files.len(), 3);
        assert_eq!(j.files[0].filename, b"empty");
        assert_eq!(j.files[0].data, b"");
        assert_eq!(j.files[1].filename, b"two.bin");
        assert_eq!(j.files[1].data.len(), 1024);
        assert_eq!(j.files[2].filename, b"x/one.bin");
        assert_eq!(j.files[2].data, b"first");
    }

    #[test]
    fn jidac_rejects_non_journal_stream() {
        let plain = crate::compress::zpaq::encode::encode(b"x", 1);
        assert!(matches!(decode_jidac(&plain), Err(Error::InvalidData(_))));
        assert!(decode_jidac(b"garbage").is_err());
    }

    /// Dev-only interop helper: dumps a JIDAC archive for the
    /// upstream `zpaq` CLI under /tmp. Run with ZPAQ_DUMP=1.
    #[cfg(feature = "std")]
    #[test]
    fn dump_jidac_fixture() {
        if std::env::var_os("ZPAQ_DUMP").is_none() {
            return;
        }
        let enc = encode_jidac(
            &[
                entry("dir/hello.txt", b"hello jidac"),
                entry("bin.dat", &[0xABu8; 777]),
            ],
            20_250_101_120_000,
            2,
        )
        .unwrap();
        std::fs::write("/tmp/rust_jidac.zpaq", enc).unwrap();
    }

    /// Dev-only interop check: decodes an upstream `zpaq a` archive
    /// given via ZPAQ_JIDAC_IN=<path> and prints the file table.
    #[cfg(feature = "std")]
    #[test]
    fn decode_upstream_jidac_oracle() {
        let Some(path) = std::env::var_os("ZPAQ_JIDAC_IN") else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let j = decode_jidac(&data).unwrap();
        eprintln!("versions: {}", j.versions.len());
        for (i, v) in j.versions.iter().enumerate() {
            for f in &v.files {
                eprintln!(
                    "v{} {} {} bytes {}",
                    i,
                    f.date,
                    f.data.len(),
                    String::from_utf8_lossy(&f.filename)
                );
            }
        }
        for f in &j.files {
            eprintln!(
                "{} {} bytes {}",
                f.date,
                f.data.len(),
                String::from_utf8_lossy(&f.filename)
            );
        }
    }

    /// Upstream `zpaq a -m3` archive whose PCOMP EOS run needs more
    /// than 1<<24 ZPAQL cycles (found by original-compress fuzzing,
    /// seed 1791135713545052870 iter 61). Guards the raised
    /// `compress::zpaq::zpaql` execution bound. Regenerate with:
    /// `zpaq a fixture.zpaq <409600-byte input> -m3 -threads 1`.
    #[test]
    fn decode_upstream_jidac_heavy_pcomp() {
        let data =
            include_bytes!("../../../tests/fixtures/zpaq/jidac-m3-heavy-pcomp.upstream.zpaq");
        let j = decode_jidac(data).unwrap();
        assert_eq!(j.versions.len(), 1);
        assert_eq!(j.files.len(), 1);
        assert_eq!(j.files[0].filename, b"s400.bin");
        assert_eq!(j.files[0].data.len(), 409_600);
        let want: [u8; 20] = [
            0x4e, 0x85, 0xca, 0x3c, 0xeb, 0xc9, 0x21, 0x2d, 0x8a, 0xff, 0x5b, 0x65, 0x96, 0x1e,
            0x78, 0xb5, 0x0f, 0x02, 0x92, 0xe0,
        ];
        assert_eq!(sha1(&j.files[0].data), want);
    }

    #[test]
    fn jidac_rejects_bad_name_and_date() {
        assert!(parse_filename(b"short").is_err());
        assert!(parse_filename(b"jDC18990101120000i0000000001").is_err());
        assert!(parse_filename(b"jDC20250101120000i0000000001").is_ok());
    }
}
