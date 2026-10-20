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
//! Read support is [`decode_jidac`], which resolves fragment
//! references into file contents, and [`decode_jidac_index`], a
//! metadata-only view that never requires `d` block contents and
//! therefore also decodes spec §8 index archives (journaling archives
//! with no `d` blocks, e.g. produced by upstream `zpaq x -index`).
//! [`encode_jidac`] writes a fresh
//! single-transaction archive; [`JidacAppender`] appends new
//! transactions to an existing archive with upstream content-defined
//! fragmenting and SHA-1 fragment deduplication, and [`JidacAppender::delete`]
//! emits deletion records.

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

/// One fragment's metadata as recorded by an `h` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JidacFragment {
    /// SHA-1 of the uncompressed fragment contents.
    pub sha1: [u8; 20],
    /// Uncompressed fragment size in bytes.
    pub size: u32,
}

/// One file's metadata recovered from `i` blocks. Fragment
/// references are left as ids; contents are not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JidacIndexFile {
    /// Raw filename bytes.
    pub filename: Vec<u8>,
    /// `yyyymmddhhmmss` timestamp, or 0 if the index recorded none.
    pub date: i64,
    /// Packed attributes (`attr << 8 | 'u'` unix / `'w'` windows), or 0.
    pub attr: u64,
    /// Referenced fragment ids, in order (unresolved).
    pub fragments: Vec<u32>,
    /// Total uncompressed size: the sum of the `size` fields of all
    /// referenced fragments. `None` when at least one referenced id
    /// has no `h`-block record in this stream — possible for an
    /// index that does not describe every fragment it references.
    pub size: Option<u64>,
}

/// One committed transaction's metadata view: the file table visible
/// after its `i` blocks were applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JidacIndexVersion {
    /// `yyyymmddhhmmss` transaction date from the `c` block filename.
    pub date: i64,
    /// Files visible at the end of this transaction.
    pub files: Vec<JidacIndexFile>,
}

/// A decoded metadata-only JIDAC view (spec §8 index).
///
/// Returned by [`decode_jidac_index`]: file metadata and the fragment
/// table without any fragment contents, so `d`-block-less index
/// archives decode the same way as full journaling archives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JidacIndex {
    /// Fragment metadata table built from `h` blocks: fragment id →
    /// SHA-1 + uncompressed size. Upstream reserves fragment id 0, so
    /// real ids start at 1; ids never described by an `h` block are
    /// absent.
    pub fragments: BTreeMap<u32, JidacFragment>,
    /// Committed transactions in stream order.
    pub versions: Vec<JidacIndexVersion>,
    /// Files visible after all committed transactions.
    pub files: Vec<JidacIndexFile>,
    /// Byte offset where committed data ends: the start of a trailing
    /// incomplete transaction, or `input.len()` when the stream ends
    /// cleanly. Same semantics as [`JidacAppender::committed_len`].
    pub committed_len: usize,
}

#[derive(Clone)]
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

/// Per-transaction file-table snapshot taken after the last `i`
/// block of the transaction.
struct VersionSnap {
    date: i64,
    files: BTreeMap<Vec<u8>, FileRecord>,
}

struct JidacState {
    /// Decoded fragment contents (full decode only; empty in
    /// metadata-only mode).
    frags: Vec<Vec<u8>>,
    /// Fragment metadata collected from `h` blocks.
    ht: BTreeMap<u32, JidacFragment>,
    dt: BTreeMap<Vec<u8>, FileRecord>,
    versions: Vec<VersionSnap>,
    /// Byte offset where committed data ends: the start of a trailing
    /// incomplete transaction, or `input.len()` when the stream ends
    /// cleanly.
    committed_len: usize,
}

/// Walk the JIDAC block sequence. With `metadata_only`, `d` block
/// payloads are not stored and `h` records are not verified against
/// fragment data, so spec §8 index archives (no `d` blocks) decode.
fn decode_state(input: &[u8], metadata_only: bool) -> Result<JidacState, Error> {
    let mut frags: Vec<Vec<u8>> = Vec::new();
    let mut ht: BTreeMap<u32, JidacFragment> = BTreeMap::new();
    let mut dt: BTreeMap<Vec<u8>, FileRecord> = BTreeMap::new();
    let mut versions: Vec<VersionSnap> = Vec::new();
    let mut saw_jidac = false;
    let mut incomplete = false;
    let mut committed_len = input.len();

    let mut start = 0;
    // Bound total ZPAQL work across every block of this decode.
    let budget = crate::compress::zpaq::zpaql::new_shared_budget();
    while !incomplete {
        let Some(header) = parse_block_header_at(input, start)? else {
            break;
        };
        let mut block = BlockDecoder::new(input, &header, usize::MAX)?;
        block.set_cycle_budget(budget.clone());
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
            // Spec §8: num range is 0000000001..4294967295. Upstream
            // enforces num >= 1 on h blocks ("bad h fragment"); a
            // num=0 d block would shift fragment ids and silently
            // return wrong data, so reject it for all block types.
            if num == 0 {
                return Err(Error::InvalidData("zpaq jidac: bad fragment"));
            }
            let payload = &segment.data;
            match ftype {
                b'c' => {
                    if payload.len() != usize_field as usize || payload.len() < 8 {
                        return Err(Error::InvalidData("zpaq jidac: bad c block size"));
                    }
                    let jmp = btol(payload)?;
                    if jmp < 0 {
                        incomplete = true;
                        committed_len = start;
                        break;
                    }
                    versions.push(VersionSnap {
                        date: fdate,
                        files: BTreeMap::new(),
                    });
                }
                b'd' if metadata_only => {
                    // Metadata-only decode keeps no fragment contents;
                    // the fragment table is rebuilt from `h` blocks.
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
                        let frag_end = off
                            .checked_add(s)
                            .ok_or(Error::InvalidData("zpaq jidac: fragment data overflow"))?;
                        let frag = payload
                            .get(off..frag_end)
                            .ok_or(Error::InvalidData("zpaq jidac: fragment data out of range"))?;
                        frags.push(frag.to_vec());
                        off = frag_end;
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
                    // Record sha1/usize into the fragment table; in
                    // full mode also verify sizes against stored data.
                    let mut s = 4usize;
                    for i in 0..n {
                        let id64 = u64::from(num) + i as u64;
                        if id64 > u64::from(u32::MAX) {
                            return Err(Error::InvalidData("zpaq jidac: bad fragment"));
                        }
                        let id = id64 as u32;
                        let mut sum = [0u8; 20];
                        let sum_end = s
                            .checked_add(20)
                            .ok_or(Error::InvalidData("zpaq jidac: bad fragment record"))?;
                        let rec_end = s
                            .checked_add(24)
                            .ok_or(Error::InvalidData("zpaq jidac: bad fragment record"))?;
                        sum.copy_from_slice(&payload[s..sum_end]);
                        let recorded = btoi(&payload[sum_end..rec_end])?;
                        ht.insert(
                            id,
                            JidacFragment {
                                sha1: sum,
                                size: recorded,
                            },
                        );
                        if !metadata_only {
                            match frags.get(id as usize) {
                                Some(frag) if frag.len() == recorded as usize => {}
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
                        v.files = dt.clone();
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
    Ok(JidacState {
        frags,
        ht,
        dt,
        versions,
        committed_len,
    })
}

/// Build the metadata-only view of one file table snapshot.
fn snapshot_index(
    dt: &BTreeMap<Vec<u8>, FileRecord>,
    ht: &BTreeMap<u32, JidacFragment>,
) -> Vec<JidacIndexFile> {
    let mut files = Vec::with_capacity(dt.len());
    for (filename, rec) in dt {
        let mut size = Some(0u64);
        for &p in &rec.ptrs {
            match ht.get(&p) {
                Some(f) => {
                    size = size.and_then(|acc| acc.checked_add(u64::from(f.size)));
                }
                None => size = None,
            }
        }
        files.push(JidacIndexFile {
            filename: filename.clone(),
            date: rec.date,
            attr: rec.attr,
            fragments: rec.ptrs.clone(),
            size,
        });
    }
    files
}

/// Decode an upstream JIDAC journaling archive.
///
/// Returns the committed versions and the latest file view. Streams
/// that mix JIDAC and plain segments, contain malformed JIDAC
/// metadata, or reference missing fragments are rejected. A trailing
/// incomplete transaction (`jmp < 0`) is ignored like upstream does.
pub fn decode_jidac(input: &[u8]) -> Result<JidacJournal, Error> {
    let state = decode_state(input, false)?;
    let mut versions = Vec::with_capacity(state.versions.len());
    for v in &state.versions {
        versions.push(JidacVersion {
            date: v.date,
            files: snapshot(&v.files, &state.frags)?,
        });
    }
    let files = snapshot(&state.dt, &state.frags)?;
    Ok(JidacJournal { versions, files })
}

/// Decode only the metadata of a JIDAC journaling stream.
///
/// Unlike [`decode_jidac`], fragment contents are never required or
/// decoded: `i`-block fragment references are returned as id lists
/// and the fragment table is built from `h` blocks alone. This also
/// decodes spec §8 index archives — journaling archives with no `d`
/// blocks, as produced by upstream `zpaq x -index` — for which
/// [`decode_jidac`] fails on the unresolvable fragment references.
/// Applied to a regular journaling archive it returns the same file
/// table and version history, plus [`JidacFragment`] metadata for
/// every `h`-block record.
pub fn decode_jidac_index(input: &[u8]) -> Result<JidacIndex, Error> {
    let state = decode_state(input, true)?;
    let mut versions = Vec::with_capacity(state.versions.len());
    for v in &state.versions {
        versions.push(JidacIndexVersion {
            date: v.date,
            files: snapshot_index(&v.files, &state.ht),
        });
    }
    let files = snapshot_index(&state.dt, &state.ht);
    Ok(JidacIndex {
        fragments: state.ht,
        versions,
        files,
        committed_len: state.committed_len,
    })
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
        if e.filename.len() > 65535 {
            return Err(Error::InvalidData("zpaq jidac: filename too long"));
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

/// Split `data` into content-defined fragments the way upstream
/// `zpaq add` does (zpaq.cpp): a rolling hash `h` is updated per byte
/// (`h=(h+c+1)*314159265` when the byte equals its order-1 context
/// prediction, `*271828182` otherwise) and a boundary is taken when
/// `h < 2^(22-frag)` after at least `64<<frag` bytes, with a hard cap
/// of `8128<<frag` bytes. `frag` is the upstream `-fragment` argument
/// (default 6: ~4KiB min, ~64KiB average, ~508KiB max). Upstream
/// additionally clamps the fragment cap to `blocksize-12` for small
/// `-blocksize` settings; the writer here is unbounded, which is
/// wire-compatible but can produce fragments larger than a
/// constrained upstream run would.
fn split_fragments(data: &[u8], frag: u32) -> Vec<&[u8]> {
    let max = if frag > 19 {
        usize::MAX
    } else {
        8128usize << frag
    };
    let min = if frag > 25 {
        max
    } else {
        (64usize << frag).min(max)
    };
    let bound = if frag <= 22 { 1u32 << (22 - frag) } else { 0 };
    let mut out = Vec::new();
    let mut o1 = [0u8; 256];
    let mut prev = 0u8;
    let mut h = 0u32;
    let mut start = 0usize;
    for (i, &c) in data.iter().enumerate() {
        if c == o1[prev as usize] {
            h = h.wrapping_add(u32::from(c) + 1).wrapping_mul(314159265);
        } else {
            h = h.wrapping_add(u32::from(c) + 1).wrapping_mul(271828182);
        }
        o1[prev as usize] = c;
        prev = c;
        let sz = i - start + 1;
        if sz >= max || (h < bound && sz >= min) {
            out.push(&data[start..=i]);
            start = i + 1;
            h = 0;
            o1 = [0; 256];
            prev = 0;
        }
    }
    if start < data.len() {
        out.push(&data[start..]);
    }
    out
}

/// Incremental appender for JIDAC archives: the write side of
/// upstream `zpaq add` semantics. [`JidacAppender::open`] decodes an
/// existing archive to rebuild the fragment and file tables, `add`
/// splits new data into content-defined fragments and reuses existing
/// fragment ids by SHA-1 (upstream dedup), `delete` records
/// deletion entries, and `commit` returns the `c`/`d`/`h`/`i`
/// transaction bytes to append to the archive.
///
/// Unlike upstream (which writes `jmp = -1` then rewrites in place),
/// committed transactions are emitted directly with a positive `jmp`;
/// readers accept both forms. Each commit emits at most one `d` and
/// `h` block rather than splitting at the upstream blocksize limit.
pub struct JidacAppender {
    /// sha1(fragment) -> fragment id over all existing + new fragments.
    frag_ids: BTreeMap<[u8; 20], u32>,
    /// Latest file table (filename -> record) for delete/skip checks.
    dt: BTreeMap<Vec<u8>, FileRecord>,
    /// Next fragment id (`htsize`, including upstream's reserved id 0).
    frag_count: u32,
    /// Offset past which `open` input was an ignored incomplete
    /// transaction; callers should truncate the archive here before
    /// appending `commit` output.
    committed_len: usize,
    /// `-fragment` equivalent, default 6.
    frag_bits: u32,
    /// New fragments staged for the next commit.
    new_frags: Vec<Vec<u8>>,
    /// Staged adds: (date, filename, attr, fragment ptrs).
    adds: Vec<(i64, Vec<u8>, u64, Vec<u32>)>,
    /// Staged deletions.
    deletes: Vec<Vec<u8>>,
}

impl JidacAppender {
    /// Open an existing JIDAC archive for appending. The archive must
    /// decode as a valid JIDAC stream (`decode_jidac` rules).
    pub fn open(existing: &[u8]) -> Result<Self, Error> {
        let state = decode_state(existing, false)?;
        let mut frag_ids = BTreeMap::new();
        for (i, frag) in state.frags.iter().enumerate().skip(1) {
            frag_ids.insert(sha1(frag), i as u32);
        }
        Ok(Self {
            frag_ids,
            dt: state.dt,
            frag_count: state.frags.len() as u32,
            committed_len: state.committed_len,
            frag_bits: 6,
            new_frags: Vec::new(),
            adds: Vec::new(),
            deletes: Vec::new(),
        })
    }

    /// Byte offset where committed data in the `open` input ends.
    /// If the archive ended with an incomplete transaction, truncate
    /// the archive to this length before appending [`Self::commit`]
    /// output, like upstream `zpaq add` does.
    pub fn committed_len(&self) -> usize {
        self.committed_len
    }

    /// Override the fragment-size parameter (upstream `-fragment`,
    /// default 6). Clamped to `0..=18` so `8128 << frag_bits` stays
    /// below `u32::MAX`. Must be set before `add` calls to affect
    /// them.
    pub fn set_fragment_bits(&mut self, bits: u32) {
        self.frag_bits = bits.min(18);
    }

    /// Stage `input` for addition. Content is split into fragments and
    /// existing fragments are reused by SHA-1. If an identical file
    /// (same resolved fragments, date, and attributes) is already
    /// present, no index entry is emitted — matching upstream's
    /// unchanged-file skip.
    pub fn add(&mut self, input: &JidacInput) -> Result<(), Error> {
        if input.filename.contains(&0) {
            return Err(Error::InvalidData("zpaq jidac: NUL in filename"));
        }
        if input.filename.len() > 65535 {
            return Err(Error::InvalidData("zpaq jidac: filename too long"));
        }
        let mut ptrs = Vec::new();
        for frag in split_fragments(input.data, self.frag_bits) {
            let sum = sha1(frag);
            let id = match self.frag_ids.get(&sum) {
                Some(&id) => id,
                None => {
                    let id = self.frag_count;
                    self.frag_count += 1;
                    self.frag_ids.insert(sum, id);
                    self.new_frags.push(frag.to_vec());
                    id
                }
            };
            ptrs.push(id);
        }
        let name = input.filename.to_vec();
        self.deletes.retain(|d| *d != name);
        if let Some(rec) = self.dt.get(&name) {
            let fdate = if input.date == 0 {
                rec.date
            } else {
                input.date
            };
            if rec.ptrs == ptrs && rec.date == fdate && rec.attr == input.attr {
                return Ok(());
            }
        }
        self.adds.push((input.date, name, input.attr, ptrs));
        Ok(())
    }

    /// Stage `filename` for deletion. Mirrors upstream: a record is
    /// emitted only for a file present in the archive's file table.
    /// Staging an `add` for the same name cancels a pending delete.
    pub fn delete(&mut self, filename: &[u8]) {
        if self.dt.contains_key(filename) && !self.deletes.iter().any(|d| d.as_slice() == filename)
        {
            self.deletes.push(filename.to_vec());
        }
        self.dt.remove(filename);
    }

    /// Emit the staged transaction (`c`/`d`/`h`/`i` blocks) and return
    /// the bytes to append to the archive. `date` is the
    /// `yyyymmddhhmmss` transaction timestamp; `level` is the model
    /// level `1..=3` used for the `d` block (metadata blocks are
    /// emitted at level 1 like upstream). Returns an empty vector when
    /// nothing is staged.
    pub fn commit(&mut self, date: i64, level: u8) -> Result<Vec<u8>, Error> {
        if !(1..=3).contains(&level) {
            return Err(Error::InvalidData("zpaq jidac: level must be 1..=3"));
        }
        if self.adds.is_empty() && self.deletes.is_empty() && self.new_frags.is_empty() {
            return Ok(Vec::new());
        }
        let first_id = self.frag_count - self.new_frags.len() as u32;

        // d block: new fragment data + sizes + 0 + count.
        let mut dpayload = Vec::new();
        for frag in &self.new_frags {
            dpayload.extend_from_slice(frag);
        }
        for frag in &self.new_frags {
            dpayload.extend_from_slice(&(frag.len() as u32).to_le_bytes());
        }
        dpayload.extend_from_slice(&0u32.to_le_bytes());
        dpayload.extend_from_slice(&(self.new_frags.len() as u32).to_le_bytes());
        let mut dblock = Vec::new();
        if !self.new_frags.is_empty() {
            emit_block(
                &mut dblock,
                level,
                &jidac_name(date, b'd', first_id)?,
                &jidac_comment(dpayload.len()),
                &dpayload,
            )?;
        }

        let mut out = Vec::new();
        // c block: jmp = compressed size of the d blocks; num = htsize.
        emit_block(
            &mut out,
            1,
            &jidac_name(date, b'c', self.frag_count)?,
            &jidac_comment(8),
            &(dblock.len() as i64).to_le_bytes(),
        )?;
        out.extend_from_slice(&dblock);

        // h block: bsize + sha1[20] usize[4] per new fragment.
        if !self.new_frags.is_empty() {
            let mut hpayload = Vec::new();
            hpayload.extend_from_slice(&(dblock.len() as u32).to_le_bytes());
            for frag in &self.new_frags {
                hpayload.extend_from_slice(&sha1(frag));
                hpayload.extend_from_slice(&(frag.len() as u32).to_le_bytes());
            }
            emit_block(
                &mut out,
                1,
                &jidac_name(date, b'h', first_id)?,
                &jidac_comment(hpayload.len()),
                &hpayload,
            )?;
        }

        // i block: delete records first (upstream order), then adds.
        let mut ipayload = Vec::new();
        for name in &self.deletes {
            if name.len() > 65535 {
                return Err(Error::InvalidData("zpaq jidac: filename too long"));
            }
            ipayload.extend_from_slice(&0i64.to_le_bytes());
            ipayload.extend_from_slice(name);
            ipayload.push(0);
        }
        for (edate, name, attr, ptrs) in &self.adds {
            let fdate = if *edate == 0 { date } else { *edate };
            ipayload.extend_from_slice(&fdate.to_le_bytes());
            ipayload.extend_from_slice(name);
            ipayload.push(0);
            if *attr == 0 {
                ipayload.extend_from_slice(&0u32.to_le_bytes());
            } else if (*attr & 0xFF) == u64::from(b'u') {
                ipayload.extend_from_slice(&3u32.to_le_bytes());
                ipayload.extend_from_slice(&(*attr as u32).to_le_bytes()[..3]);
            } else if (*attr & 0xFF) == u64::from(b'w') {
                ipayload.extend_from_slice(&5u32.to_le_bytes());
                ipayload.extend_from_slice(&(*attr as u32).to_le_bytes()[..4]);
                ipayload.push((attr >> 32) as u8);
            } else {
                ipayload.extend_from_slice(&0u32.to_le_bytes());
            }
            ipayload.extend_from_slice(&(ptrs.len() as u32).to_le_bytes());
            for &p in ptrs {
                ipayload.extend_from_slice(&p.to_le_bytes());
            }
        }
        emit_block(
            &mut out,
            1,
            &jidac_name(date, b'i', 1)?,
            &jidac_comment(ipayload.len()),
            &ipayload,
        )?;

        // Reflect the committed state so a subsequent commit on the
        // same appender sees the updated file table.
        for name in self.deletes.drain(..) {
            self.dt.remove(&name);
        }
        for (edate, name, attr, ptrs) in self.adds.drain(..) {
            let fdate = if edate == 0 { date } else { edate };
            self.dt.insert(
                name,
                FileRecord {
                    date: fdate,
                    attr,
                    ptrs,
                },
            );
        }
        self.new_frags.clear();
        Ok(out)
    }
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
        std::fs::write("/tmp/rust_jidac.zpaq", &enc).unwrap();
        let mut ap = JidacAppender::open(&enc).unwrap();
        let mut bigger = b"delta payload ".to_vec();
        bigger.extend_from_slice(&[9u8; 5000]);
        ap.add(&entry("dir/extra.log", &bigger)).unwrap();
        let suffix = ap.commit(20_250_102_120_000, 1).unwrap();
        let mut appended = enc;
        appended.extend_from_slice(&suffix);
        std::fs::write("/tmp/rust_jidac_appended.zpaq", &appended).unwrap();
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
    fn jidac_append_roundtrip_and_delete() {
        let base = encode_jidac(
            &[entry("a.txt", b"alpha"), entry("b.bin", &[7u8; 9000])],
            20_250_101_120_000,
            1,
        )
        .unwrap();
        let mut ap = JidacAppender::open(&base).unwrap();
        ap.add(&entry("c.log", b"tail")).unwrap();
        ap.delete(b"a.txt");
        let suffix = ap.commit(20_250_102_120_000, 1).unwrap();
        assert!(!suffix.is_empty());
        let mut archive = base.clone();
        archive.extend_from_slice(&suffix);
        let j = decode_jidac(&archive).unwrap();
        assert_eq!(j.versions.len(), 2);
        assert_eq!(j.files.len(), 2);
        assert_eq!(j.files[0].filename, b"b.bin");
        assert_eq!(j.files[1].filename, b"c.log");
        assert_eq!(j.files[1].data, b"tail");
        // v0 still shows the pre-delete view.
        assert_eq!(j.versions[0].files.len(), 2);
        assert_eq!(j.versions[0].files[0].filename, b"a.txt");
    }

    #[test]
    fn jidac_append_dedup_reuses_fragments() {
        let blob: Vec<u8> = (0..60000).map(|i| (i * 7 % 251) as u8).collect();
        let base = encode_jidac(&[entry("one.bin", &blob)], 20_250_101_120_000, 1).unwrap();
        let mut ap = JidacAppender::open(&base).unwrap();
        ap.add(&entry("two.bin", &blob)).unwrap();
        let suffix = ap.commit(20_250_102_120_000, 1).unwrap();
        // No new fragments: the transaction is metadata-only (c + i).
        assert!(suffix.len() < 2048);
        let mut archive = base;
        archive.extend_from_slice(&suffix);
        let j = decode_jidac(&archive).unwrap();
        assert_eq!(j.files.len(), 2);
        assert_eq!(j.files[0].data, blob);
        assert_eq!(j.files[1].data, blob);
    }

    #[test]
    fn jidac_append_unchanged_is_noop() {
        let base = encode_jidac(&[entry("a.txt", b"alpha")], 20_250_101_120_000, 1).unwrap();
        let mut ap = JidacAppender::open(&base).unwrap();
        ap.add(&entry("a.txt", b"alpha")).unwrap();
        assert!(ap.commit(20_250_102_120_000, 1).unwrap().is_empty());
        // Different content under the same name does emit.
        let mut ap = JidacAppender::open(&base).unwrap();
        ap.add(&entry("a.txt", b"changed")).unwrap();
        assert!(!ap.commit(20_250_102_120_000, 1).unwrap().is_empty());
        // Deleting an absent name is a no-op.
        let mut ap = JidacAppender::open(&base).unwrap();
        ap.delete(b"ghost");
        assert!(ap.commit(20_250_102_120_000, 1).unwrap().is_empty());
    }

    /// `jidac-appended-mixed.zpaq` was produced by `encode_jidac`
    /// (2 files), then `JidacAppender` (1 file), then upstream
    /// `zpaq a -m1` (1 file): a three-version chain mixing our and
    /// upstream transactions.
    #[test]
    fn decode_jidac_appended_mixed() {
        let arc = include_bytes!("../../../tests/fixtures/zpaq/jidac-appended-mixed.zpaq");
        let j = decode_jidac(arc).unwrap();
        assert_eq!(j.versions.len(), 3);
        assert_eq!(j.versions[0].files.len(), 2);
        assert_eq!(j.versions[1].files.len(), 3);
        assert_eq!(j.files.len(), 4);
        assert_eq!(j.files[0].filename, b"bin.dat");
        assert_eq!(j.files[0].data.len(), 777);
        assert_eq!(j.files[1].filename, b"dir/extra.log");
        assert_eq!(j.files[1].data.len(), 5014);
        assert_eq!(&j.files[1].data[..14], b"delta payload ");
        assert_eq!(j.files[2].filename, b"dir/hello.txt");
        assert_eq!(j.files[2].data, b"hello jidac");
        assert_eq!(j.files[3].filename, b"new.txt");
        assert_eq!(j.files[3].data, b"newfile-content\n");
    }

    /// An archive ending in an incomplete transaction (jmp = -1) is
    /// truncated via `committed_len` before appending, matching
    /// upstream `zpaq add` behavior.
    #[test]
    fn jidac_append_truncates_incomplete_tail() {
        let base = encode_jidac(&[entry("a.txt", b"alpha")], 20_250_101_120_000, 1).unwrap();
        let mut truncated = base.clone();
        emit_block(
            &mut truncated,
            1,
            &jidac_name(20_250_102_120_000, b'c', 1).unwrap(),
            &jidac_comment(8),
            &(-1i64).to_le_bytes(),
        )
        .unwrap();
        let mut ap = JidacAppender::open(&truncated).unwrap();
        assert_eq!(ap.committed_len(), base.len());
        ap.add(&entry("b.txt", b"beta")).unwrap();
        let suffix = ap.commit(20_250_103_120_000, 1).unwrap();
        let mut archive = base;
        archive.extend_from_slice(&suffix);
        let j = decode_jidac(&archive).unwrap();
        assert_eq!(j.versions.len(), 2);
        assert_eq!(j.files.len(), 2);
        assert_eq!(j.files[1].data, b"beta");
    }

    #[test]
    fn jidac_rejects_bad_name_and_date() {
        assert!(parse_filename(b"short").is_err());
        assert!(parse_filename(b"jDC18990101120000i0000000001").is_err());
        assert!(parse_filename(b"jDC20250101120000i0000000001").is_ok());
    }

    #[test]
    fn jidac_rejects_oversized_filename() {
        let long_name = alloc::vec![b'a'; 65536];
        let input = JidacInput {
            filename: &long_name,
            date: 20_250_101_120_000,
            attr: 0,
            data: b"x",
        };
        assert!(matches!(
            encode_jidac(core::slice::from_ref(&input), 20_250_101_120_000, 1),
            Err(Error::InvalidData("zpaq jidac: filename too long"))
        ));

        let base = encode_jidac(&[entry("a.txt", b"alpha")], 20_250_101_120_000, 1).unwrap();
        let mut ap = JidacAppender::open(&base).unwrap();
        assert!(matches!(
            ap.add(&input),
            Err(Error::InvalidData("zpaq jidac: filename too long"))
        ));
    }

    /// Build a spec §8 index archive by hand: `c` (jmp = 0), `h`, and
    /// `i` blocks describing one file backed by fragment 1, with no
    /// `d` block — the fragment data lives in the archive this index
    /// describes.
    fn index_archive() -> Vec<u8> {
        let date = 20_250_101_120_000i64;
        let data = b"index payload data";
        let attr: u64 = (0o100644u64 << 8) | u64::from(b'u');
        let mut arc = Vec::new();
        // c block: upstream writes jmp = 0 for an index transaction.
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'c', 2).unwrap(),
            &jidac_comment(8),
            &0i64.to_le_bytes(),
        )
        .unwrap();
        // h block: bsize (compressed d-block size in the described
        // archive) + sha1[20] usize[4] for fragment 1.
        let mut h = Vec::new();
        h.extend_from_slice(&120u32.to_le_bytes());
        h.extend_from_slice(&sha1(data));
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'h', 1).unwrap(),
            &jidac_comment(h.len()),
            &h,
        )
        .unwrap();
        // i block: one add entry pointing at fragment 1.
        let mut i = Vec::new();
        i.extend_from_slice(&date.to_le_bytes());
        i.extend_from_slice(b"meta.txt");
        i.push(0);
        i.extend_from_slice(&3u32.to_le_bytes());
        i.extend_from_slice(&(attr as u32).to_le_bytes()[..3]);
        i.extend_from_slice(&1u32.to_le_bytes());
        i.extend_from_slice(&1u32.to_le_bytes());
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'i', 1).unwrap(),
            &jidac_comment(i.len()),
            &i,
        )
        .unwrap();
        arc
    }

    #[test]
    fn jidac_index_decodes_index_archive() {
        let arc = index_archive();
        let idx = decode_jidac_index(&arc).unwrap();
        assert_eq!(idx.versions.len(), 1);
        assert_eq!(idx.versions[0].date, 20_250_101_120_000);
        assert_eq!(idx.files.len(), 1);
        let f = &idx.files[0];
        assert_eq!(f.filename, b"meta.txt");
        assert_eq!(f.date, 20_250_101_120_000);
        assert_eq!(f.attr, (0o100644u64 << 8) | u64::from(b'u'));
        assert_eq!(f.fragments, [1]);
        assert_eq!(f.size, Some(18));
        let frag = idx.fragments.get(&1).unwrap();
        assert_eq!(frag.sha1, sha1(b"index payload data"));
        assert_eq!(frag.size, 18);
        assert_eq!(idx.fragments.len(), 1);
        assert_eq!(idx.versions[0].files, idx.files);
        assert_eq!(idx.committed_len, arc.len());
        // The same stream is rejected by the full decoder because
        // fragment data is absent.
        assert!(matches!(
            decode_jidac(&arc),
            Err(Error::InvalidData(
                "zpaq jidac: fragment table without data"
            ))
        ));
    }

    #[test]
    fn jidac_index_unknown_fragment_size() {
        // An index may reference fragments it does not describe:
        // ptr 7 has no h record, so size is unknown.
        let date = 20_250_101_120_000i64;
        let mut arc = Vec::new();
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'c', 1).unwrap(),
            &jidac_comment(8),
            &0i64.to_le_bytes(),
        )
        .unwrap();
        let mut i = Vec::new();
        i.extend_from_slice(&date.to_le_bytes());
        i.extend_from_slice(b"ext.bin");
        i.push(0);
        i.extend_from_slice(&0u32.to_le_bytes());
        i.extend_from_slice(&2u32.to_le_bytes());
        i.extend_from_slice(&7u32.to_le_bytes());
        i.extend_from_slice(&3u32.to_le_bytes());
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'i', 1).unwrap(),
            &jidac_comment(i.len()),
            &i,
        )
        .unwrap();
        let idx = decode_jidac_index(&arc).unwrap();
        assert_eq!(idx.files.len(), 1);
        assert_eq!(idx.files[0].fragments, [7, 3]);
        assert_eq!(idx.files[0].size, None);
        assert!(idx.fragments.is_empty());
    }

    #[test]
    fn jidac_index_full_archive_metadata() {
        // A regular journaling archive decodes metadata-only too:
        // the fragment table comes from the h block, file ptrs stay
        // unresolved.
        let data = b"journal payload";
        let enc = encode_jidac(
            &[
                entry("a.txt", data),
                JidacInput {
                    filename: b"dir/b.bin",
                    date: 20_250_101_130_000,
                    attr: (0o100600u64 << 8) | u64::from(b'u'),
                    data: b"second",
                },
            ],
            20_250_101_120_000,
            1,
        )
        .unwrap();
        let idx = decode_jidac_index(&enc).unwrap();
        assert_eq!(idx.versions.len(), 1);
        assert_eq!(idx.files.len(), 2);
        assert_eq!(idx.files[0].filename, b"a.txt");
        assert_eq!(idx.files[0].fragments, [1]);
        assert_eq!(idx.files[0].size, Some(15));
        assert_eq!(idx.files[1].filename, b"dir/b.bin");
        assert_eq!(idx.files[1].fragments, [2]);
        assert_eq!(idx.files[1].size, Some(6));
        assert_eq!(idx.files[1].attr, (0o100600u64 << 8) | u64::from(b'u'));
        assert_eq!(idx.fragments.len(), 2);
        assert_eq!(idx.fragments[&1].sha1, sha1(data));
        assert_eq!(idx.fragments[&1].size, 15);
        assert_eq!(idx.fragments[&2].size, 6);
        // Consistent with the full decode of the same stream.
        let j = decode_jidac(&enc).unwrap();
        assert_eq!(idx.files.len(), j.files.len());
        for (m, f) in idx.files.iter().zip(&j.files) {
            assert_eq!(m.filename, f.filename);
            assert_eq!(m.date, f.date);
            assert_eq!(m.attr, f.attr);
            assert_eq!(m.size, Some(f.data.len() as u64));
        }
    }

    #[test]
    fn jidac_index_multi_version_history() {
        // Second transaction reuses fragment 1 by dedup: it emits only
        // c + i blocks. The index view keeps per-version snapshots.
        let data = b"shared";
        let base = encode_jidac(&[entry("a.txt", data)], 20_250_101_120_000, 1).unwrap();
        let mut ap = JidacAppender::open(&base).unwrap();
        ap.add(&entry("b.txt", data)).unwrap();
        ap.delete(b"a.txt");
        let suffix = ap.commit(20_250_102_120_000, 1).unwrap();
        let mut arc = base;
        arc.extend_from_slice(&suffix);
        let idx = decode_jidac_index(&arc).unwrap();
        assert_eq!(idx.versions.len(), 2);
        assert_eq!(idx.versions[0].files.len(), 1);
        assert_eq!(idx.versions[0].files[0].filename, b"a.txt");
        assert_eq!(idx.versions[1].files.len(), 1);
        assert_eq!(idx.versions[1].files[0].filename, b"b.txt");
        assert_eq!(idx.versions[1].files[0].fragments, [1]);
        assert_eq!(idx.files, idx.versions[1].files);
        assert_eq!(idx.fragments.len(), 1);
        assert_eq!(idx.fragments[&1].sha1, sha1(data));
    }

    #[test]
    fn jidac_index_rejects_malformed() {
        // Non-journal input is still rejected.
        let plain = crate::compress::zpaq::encode::encode(b"x", 1);
        assert!(decode_jidac_index(&plain).is_err());
        assert!(decode_jidac_index(b"garbage").is_err());

        // Truncated i entry: nonzero date, filename, no attr field.
        let date = 20_250_101_120_000i64;
        let mut arc = Vec::new();
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'c', 1).unwrap(),
            &jidac_comment(8),
            &0i64.to_le_bytes(),
        )
        .unwrap();
        let mut i = Vec::new();
        i.extend_from_slice(&date.to_le_bytes());
        i.extend_from_slice(b"x");
        i.push(0);
        emit_block(
            &mut arc,
            1,
            &jidac_name(date, b'i', 1).unwrap(),
            &jidac_comment(i.len()),
            &i,
        )
        .unwrap();
        assert!(matches!(
            decode_jidac_index(&arc),
            Err(Error::InvalidData("zpaq jidac: missing attr"))
        ));

        // Corrupt h block payload (not 4 mod 24).
        let mut arc2 = Vec::new();
        emit_block(
            &mut arc2,
            1,
            &jidac_name(date, b'c', 1).unwrap(),
            &jidac_comment(8),
            &0i64.to_le_bytes(),
        )
        .unwrap();
        emit_block(
            &mut arc2,
            1,
            &jidac_name(date, b'h', 1).unwrap(),
            &jidac_comment(9),
            &[0u8; 9],
        )
        .unwrap();
        assert!(matches!(
            decode_jidac_index(&arc2),
            Err(Error::InvalidData("zpaq jidac: bad h block size"))
        ));
    }

    #[test]
    fn jidac_rejects_zero_num() {
        // Spec §8: num range is 0000000001..4294967295. A num=0 block
        // is rejected for every block type (upstream checks it on h).
        for ftype in *b"cdhi" {
            let mut arc = Vec::new();
            emit_block(
                &mut arc,
                1,
                &jidac_name(20_250_101_120_000, ftype, 0).unwrap(),
                &jidac_comment(8),
                &0i64.to_le_bytes(),
            )
            .unwrap();
            assert!(
                matches!(
                    decode_jidac(&arc),
                    Err(Error::InvalidData("zpaq jidac: bad fragment"))
                ),
                "ftype {}",
                ftype
            );
        }
    }
}
