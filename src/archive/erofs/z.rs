//! z_erofs compressed-inode decoding (datalayout 1 `COMPRESSED_FULL`
//! and 3 `COMPRESSED_COMPACT`).
//!
//! Implements the per-inode `z_erofs_map_header`, the non-compact
//! 8-byte `z_erofs_lcluster_index` table, compacted bit-packed
//! indexes (4-byte packs plus the optional 2-byte middle phase),
//! the `z_erofs_extent` record list (`Z_EROFS_ADVISE_EXTENTS`),
//! big pclusters via `Z_EROFS_LI_D0_CBLKCNT`, partial references and
//! hole pclusters. Per-pcluster decode supports LZ4 (raw block,
//! `LZ4_decompress_safe_partial` semantics), MicroLZMA, DEFLATE and
//! Zstandard; the latter three require the matching crate codec
//! feature (an `lzma`-family feature, `deflate`, `zstd`).
//!
//! Layouts that need the packed inode or inline tail-packing
//! (`Z_EROFS_ADVISE_FRAGMENT_PCLUSTER`, `Z_EROFS_ADVISE_INLINE_PCLUSTER`,
//! `h_clusterbits` bit 7) are reported as `Error::Unsupported`; the
//! matching superblock features are already rejected by the caller.

use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{
    DATALAYOUT_COMPRESSED_COMPACT, DATALAYOUT_COMPRESSED_FULL, Img, Inode, u16le, u32le, u64le,
};

const LCLUSTER_PLAIN: u8 = 0;
const LCLUSTER_HEAD1: u8 = 1;
const LCLUSTER_NONHEAD: u8 = 2;
const LCLUSTER_HEAD2: u8 = 3;
const LCLUSTER_TYPE_MASK: u16 = 3;

const LI_PARTIAL_REF: u16 = 1 << 15;
const LI_HOLE: u16 = 1 << 14;
const LI_D0_CBLKCNT: u16 = 1 << 11;

const ADVISE_EXTENTS: u16 = 0x0001; // COMPRESSED_FULL only
const ADVISE_COMPACTED_2B: u16 = 0x0001; // COMPRESSED_COMPACT only
const ADVISE_BIG_PCLUSTER_1: u16 = 0x0002;
const ADVISE_BIG_PCLUSTER_2: u16 = 0x0004;
const ADVISE_INLINE_PCLUSTER: u16 = 0x0008;
const ADVISE_INTERLACED_PCLUSTER: u16 = 0x0010;
const ADVISE_FRAGMENT_PCLUSTER: u16 = 0x0020;

const EXTENT_PLEN_PARTIAL: u32 = 1 << 27;
const EXTENT_PLEN_FMT_BIT: u32 = 28;
const EXTENT_PLEN_MASK: u32 = (1 << 21) - 1;

const ALG_LZ4: u8 = 0;
const ALG_LZMA: u8 = 1;
const ALG_DEFLATE: u8 = 2;
const ALG_ZSTD: u8 = 3;
const ALG_MAX: u8 = 4;

const PCLUSTER_MAX_SIZE: u64 = 1024 * 1024;
const PCLUSTER_MAX_DSIZE: u64 = 12 * 1024 * 1024;

/// Parsed `z_erofs_map_header` plus derived index geometry.
struct ZMap {
    advise: u16,
    /// HEAD1 / HEAD2 algorithm IDs (`h_algorithmtype` nibbles).
    algos: [u8; 2],
    /// `blkszbits + (h_clusterbits & 7)`.
    lclusterbits: u32,
    /// Image offset of the first index record.
    index_base: usize,
    /// Index-table entry count (`erofs_iblks`: ceil(size / blksz)).
    totalidx: usize,
    /// Compacted-index phase sizes (COMPRESSED_COMPACT only).
    c4b_init: usize,
    c2b: usize,
}

/// One decoded lcluster index entry.
enum LcIndex {
    /// PLAIN / HEAD1 / HEAD2 lcluster.
    Head {
        htype: u8,
        clusterofs: u64,
        pblk: u64,
        partial: bool,
        hole: bool,
    },
    /// NONHEAD lcluster; `cblkcnt` carries the big-pcluster block
    /// count when `Z_EROFS_LI_D0_CBLKCNT` was set.
    NonHead { cblkcnt: Option<u32> },
}

/// A pending physical extent during the sequential index scan.
struct Pend {
    /// Logical (decompressed) offset where the extent data starts.
    la: u64,
    /// Index position of the HEAD lcluster.
    lcn: u64,
    htype: u8,
    pblk: u64,
    hole: bool,
    /// Big-pcluster block count recorded by a CBLKCNT NONHEAD.
    cblks: Option<u32>,
    /// The first NONHEAD after a big-pcluster head lacked CBLKCNT.
    missing_cblkcnt: bool,
}

fn align8(v: usize) -> usize {
    v.checked_add(7).map(|v| v & !7).unwrap_or(usize::MAX)
}

/// `z_erofs_fixup_insize`: compressed streams are right-aligned in
/// the pcluster; drop leading zero padding to recover the stream.
fn strip_zero_padding(region: &[u8]) -> Result<&[u8], Error> {
    let skip = region.iter().take_while(|&&b| b == 0).count();
    if skip == region.len() {
        return Err(Error::InvalidData("erofs empty pcluster"));
    }
    Ok(&region[skip..])
}

/// Decode a raw LZ4 block, stopping as soon as `out_len` bytes have
/// been produced (`LZ4_decompress_safe_partial` semantics: trailing
/// input bytes and a partial final sequence are ignored).
fn lz4_decode_partial(src: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    let mut dst = Vec::with_capacity(out_len);
    let mut sp = 0usize;
    while sp < src.len() && dst.len() < out_len {
        let token = src[sp];
        sp += 1;
        let mut lit = usize::from(token >> 4);
        if lit == 15 {
            loop {
                let e = *src.get(sp).ok_or(Error::UnexpectedEof)?;
                sp += 1;
                lit += usize::from(e);
                if e != 255 {
                    break;
                }
            }
        }
        match sp.checked_add(lit) {
            Some(e) if e <= src.len() => {}
            _ => return Err(Error::UnexpectedEof),
        }
        let take = lit.min(out_len - dst.len());
        dst.extend_from_slice(&src[sp..sp + take]);
        sp += lit;
        if sp >= src.len() || dst.len() >= out_len {
            break;
        }
        if sp + 2 > src.len() {
            return Err(Error::UnexpectedEof);
        }
        let off = usize::from(u16le(src, sp));
        sp += 2;
        if off == 0 || off > dst.len() {
            return Err(Error::InvalidData("erofs lz4 bad match offset"));
        }
        let mut mlen = usize::from(token & 0xf);
        if mlen == 15 {
            loop {
                let e = *src.get(sp).ok_or(Error::UnexpectedEof)?;
                sp += 1;
                mlen += usize::from(e);
                if e != 255 {
                    break;
                }
            }
        }
        let take = (mlen + 4).min(out_len - dst.len());
        let start = dst.len() - off;
        for i in 0..take {
            let b = dst[start + i];
            dst.push(b);
        }
    }
    if dst.len() != out_len {
        return Err(Error::InvalidData("erofs lz4 truncated stream"));
    }
    Ok(dst)
}

/// MicroLZMA: a raw LZMA1 stream without EOS marker whose first byte
/// (always zero in raw LZMA) is replaced by the bitwise negation of
/// the properties byte.
#[cfg(any(
    feature = "lzma-alone",
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
))]
fn microlzma_decode(img: &Img<'_>, region: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    let src = strip_zero_padding(region)?;
    let (&b0, rest) = src.split_first().ok_or(Error::UnexpectedEof)?;
    let props = crate::compress::lzma::LzmaProperties::from_props_byte(!b0)
        .map_err(|_| Error::InvalidData("erofs microlzma bad properties"))?;
    let mut raw = Vec::with_capacity(rest.len() + 1);
    raw.push(0);
    raw.extend_from_slice(rest);
    let (out, _) = crate::compress::lzma::lzma_decode_with_props_and_size(
        &raw,
        img.lzma_dict_size,
        props,
        out_len,
    )?;
    Ok(out)
}

#[cfg(not(any(
    feature = "lzma-alone",
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
)))]
fn microlzma_decode(_img: &Img<'_>, _region: &[u8], _out_len: usize) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported(
        "erofs microlzma needs an lzma codec feature",
    ))
}

#[cfg(feature = "deflate")]
fn deflate_decode(region: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    let src = strip_zero_padding(region)?;
    let out = crate::compress::deflate::decode::decode(src)?;
    if out.len() < out_len {
        return Err(Error::InvalidData("erofs deflate short output"));
    }
    let mut out = out;
    out.truncate(out_len);
    Ok(out)
}

#[cfg(not(feature = "deflate"))]
fn deflate_decode(_region: &[u8], _out_len: usize) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported(
        "erofs deflate needs the deflate codec feature",
    ))
}

#[cfg(feature = "zstd")]
fn zstd_decode(region: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    let src = strip_zero_padding(region)?;
    let out = crate::compress::zstd::decode::decode(src)?;
    if out.len() < out_len {
        return Err(Error::InvalidData("erofs zstd short output"));
    }
    let mut out = out;
    out.truncate(out_len);
    Ok(out)
}

#[cfg(not(feature = "zstd"))]
fn zstd_decode(_region: &[u8], _out_len: usize) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported(
        "erofs zstd needs the zstd codec feature",
    ))
}

/// Decompress `llen` bytes of a compressed pcluster from `region`
/// (`[pstart, pstart + plen)`).
fn inflate(img: &Img<'_>, alg: u8, region: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
    match alg {
        ALG_LZ4 => {
            let src = if img.lz4_0padding {
                strip_zero_padding(region)?
            } else {
                region
            };
            lz4_decode_partial(src, out_len)
        }
        ALG_LZMA => microlzma_decode(img, region, out_len),
        ALG_DEFLATE => deflate_decode(region, out_len),
        ALG_ZSTD => zstd_decode(region, out_len),
        _ => Err(Error::Unsupported("erofs unknown compression algorithm")),
    }
}

/// `decode_compactedbits`: read the bit-packed value of pack entry
/// `i` (LSB-first within the pack bytes).
fn compacted_value(pack: &[u8], lobits: u32, encodebits: u32, i: usize) -> (u32, u8) {
    let pos = encodebits as usize * i;
    let v = u32le(pack, pos / 8) >> (pos & 7);
    (v & ((1 << lobits) - 1), ((v >> lobits) & 3) as u8)
}

/// `unpack_compacted_index` (kernel zmap.c): decode index entry `i`
/// inside the pack of `vcnt` entries of `1 << shift` bytes each
/// starting at `pack_off` in the image.
fn unpack_compacted(
    img: &Img<'_>,
    zm: &ZMap,
    pack_off: usize,
    shift: u32,
    i: usize,
) -> Result<LcIndex, Error> {
    let vcnt: usize = if shift == 2 && zm.lclusterbits <= 14 {
        2
    } else if shift == 1 && zm.lclusterbits <= 12 {
        16
    } else {
        return Err(Error::Unsupported("erofs compact index geometry"));
    };
    let packsz = vcnt << shift;
    let pack = img
        .data
        .get(pack_off..pack_off + packsz)
        .ok_or(Error::UnexpectedEof)?;
    // ilog2(Z_EROFS_LI_D0_CBLKCNT) + 1 = 12
    let lobits = zm.lclusterbits.max(12);
    let encodebits = ((packsz * 8 - 32) / vcnt) as u32;
    let base = u64::from(u32le(pack, packsz - 4));
    let (lo, ty) = compacted_value(pack, lobits, encodebits, i);
    if ty == LCLUSTER_NONHEAD {
        if lo & u32::from(LI_D0_CBLKCNT) != 0 {
            if zm.advise & (ADVISE_BIG_PCLUSTER_1 | ADVISE_BIG_PCLUSTER_2) == 0 {
                return Err(Error::InvalidData("erofs CBLKCNT w/o big pcluster"));
            }
            return Ok(LcIndex::NonHead {
                cblkcnt: Some(lo & !u32::from(LI_D0_CBLKCNT)),
            });
        }
        return Ok(LcIndex::NonHead { cblkcnt: None });
    }
    // HEAD/PLAIN entry: the pack's trailing blkaddr records the
    // previous pcluster block (non-big) or this pack's first pcluster
    // (big); walk back over the pack to accumulate the physical
    // block count.
    let mut nblk: u64 = 0;
    let mut j = i as i64;
    if zm.advise & ADVISE_BIG_PCLUSTER_1 == 0 {
        nblk = 1;
        while j > 0 {
            j -= 1;
            let (lo2, ty2) = compacted_value(pack, lobits, encodebits, j as usize);
            if ty2 == LCLUSTER_NONHEAD {
                // delta0 back to the owning head (kernel does not
                // mask the CBLKCNT bit here; non-big images never
                // carry it).
                j -= i64::from(lo2);
            }
            if j >= 0 {
                nblk += 1;
            }
        }
    } else {
        while j > 0 {
            j -= 1;
            let (lo2, ty2) = compacted_value(pack, lobits, encodebits, j as usize);
            if ty2 == LCLUSTER_NONHEAD {
                if lo2 & u32::from(LI_D0_CBLKCNT) != 0 {
                    j -= 1;
                    nblk += u64::from(lo2 & !u32::from(LI_D0_CBLKCNT));
                    continue;
                }
                if lo2 <= 1 {
                    return Err(Error::InvalidData("erofs bogus compact index"));
                }
                j -= i64::from(lo2) - 2;
                continue;
            }
            nblk += 1;
        }
    }
    if lo >= 1 << zm.lclusterbits {
        return Err(Error::InvalidData("erofs bad clusterofs"));
    }
    Ok(LcIndex::Head {
        htype: ty,
        clusterofs: u64::from(lo),
        pblk: base + nblk,
        partial: false,
        hole: false,
    })
}

/// Load the lcluster index entry `lcn` for index-based layouts,
/// mirroring kernel `z_erofs_load_full_lcluster` and
/// `z_erofs_load_compact_lcluster`.
fn load_index(img: &Img<'_>, zm: &ZMap, lcn: u64) -> Result<LcIndex, Error> {
    if zm.c4b_init == usize::MAX {
        // COMPRESSED_FULL: flat 8-byte `z_erofs_lcluster_index`.
        let pos = zm
            .index_base
            .checked_add(lcn as usize * 8)
            .ok_or(Error::InvalidData("erofs index overflow"))?;
        let d = img.data.get(pos..pos + 8).ok_or(Error::UnexpectedEof)?;
        let advise = u16le(d, 0);
        let ty = (advise & LCLUSTER_TYPE_MASK) as u8;
        if ty == LCLUSTER_NONHEAD {
            let d0 = u16le(d, 4);
            if d0 & LI_D0_CBLKCNT != 0 {
                if zm.advise & (ADVISE_BIG_PCLUSTER_1 | ADVISE_BIG_PCLUSTER_2) == 0 {
                    return Err(Error::InvalidData("erofs CBLKCNT w/o big pcluster"));
                }
                return Ok(LcIndex::NonHead {
                    cblkcnt: Some(u32::from(d0 & !LI_D0_CBLKCNT)),
                });
            }
            return Ok(LcIndex::NonHead { cblkcnt: None });
        }
        let clusterofs = u64::from(u16le(d, 2));
        if clusterofs >= 1u64 << zm.lclusterbits {
            return Err(Error::InvalidData("erofs bad clusterofs"));
        }
        let hole = advise & LI_HOLE != 0;
        let pblk = u64::from(u32le(d, 4));
        return Ok(LcIndex::Head {
            htype: ty,
            clusterofs,
            pblk,
            partial: advise & LI_PARTIAL_REF != 0,
            hole: hole || pblk == u64::from(u32::MAX),
        });
    }
    // COMPRESSED_COMPACT: three phases (initial 4-byte packs, an
    // optional 2-byte middle, trailing 4-byte packs).
    let mut pos = zm.index_base;
    let mut l = lcn as usize;
    let shift;
    if l < zm.c4b_init {
        shift = 2;
    } else {
        pos += zm.c4b_init * 4;
        l -= zm.c4b_init;
        if l < zm.c2b {
            shift = 1;
        } else {
            pos += zm.c2b * 2;
            l -= zm.c2b;
            shift = 2;
        }
    }
    pos += l << shift;
    // Reposition to the pack containing the entry.
    let vcnt: usize = if shift == 2 { 2 } else { 16 };
    let pack_off = pos & !((vcnt << shift) - 1);
    let i = (pos - pack_off) >> shift;
    unpack_compacted(img, zm, pack_off, shift, i)
}

/// Decompressed size bound check shared by both layouts.
fn check_extent_size(plen: u64, llen: u64) -> Result<(), Error> {
    if plen > PCLUSTER_MAX_SIZE || llen > PCLUSTER_MAX_DSIZE {
        return Err(Error::Unsupported("erofs oversized pcluster"));
    }
    Ok(())
}

/// Copy raw (`PLAIN`/`SHIFTED`/`INTERLACED`) extent bytes into `out`.
fn emit_raw(
    img: &Img<'_>,
    out: &mut [u8],
    la: u64,
    pa: u64,
    plen: u64,
    llen: u64,
    interlaced: bool,
) -> Result<(), Error> {
    if llen > plen {
        return Err(Error::InvalidData("erofs plain extent too small"));
    }
    let blksz = img.blksz as u64;
    let pa = usize::try_from(pa).map_err(|_| Error::InvalidData("erofs extent offset"))?;
    let la = usize::try_from(la).map_err(|_| Error::InvalidData("erofs extent offset"))?;
    let ll = llen as usize;
    let region = img
        .data
        .get(pa..pa.saturating_add(plen as usize))
        .ok_or(Error::InvalidData("erofs plain extent out of range"))?;
    if la + ll > out.len() {
        return Err(Error::InvalidData("erofs extent out of range"));
    }
    if interlaced {
        // Raw data ends block-aligned inside the pcluster: the head
        // of this extent shares a block with the previous one.
        let cur = (blksz - (la as u64 & (blksz - 1))).min(llen) as usize;
        let start = plen as usize - cur;
        out[la..la + cur].copy_from_slice(&region[start..start + cur]);
        out[la + cur..la + ll].copy_from_slice(&region[..ll - cur]);
    } else {
        out[la..la + ll].copy_from_slice(&region[..ll]);
    }
    Ok(())
}

/// Emit a pending index-layout extent `[p.la, end)` into `out`.
fn emit(img: &Img<'_>, out: &mut [u8], zm: &ZMap, p: Pend, end: u64) -> Result<(), Error> {
    let blksz = img.blksz as u64;
    if end <= p.la {
        return Err(Error::InvalidData("erofs extent out of order"));
    }
    let llen = end - p.la;
    if p.hole {
        return Ok(()); // `out` is pre-zeroed
    }
    // Physical length bound of the pcluster. Non-big pclusters are
    // exactly one filesystem block (kernel defaults compressedblks
    // to 1); under the big-pcluster advise, CBLKCNT supplies the real
    // block count and a missing one means a 1-block pcluster.
    // BIG_PCLUSTER_1 covers HEAD1, BIG_PCLUSTER_2 covers HEAD2 and
    // PLAIN alike.
    let plen = match p.htype {
        LCLUSTER_PLAIN | LCLUSTER_HEAD1 | LCLUSTER_HEAD2 => {
            let big = if p.htype == LCLUSTER_HEAD1 {
                zm.advise & ADVISE_BIG_PCLUSTER_1 != 0
            } else {
                zm.advise & ADVISE_BIG_PCLUSTER_2 != 0
            };
            if p.missing_cblkcnt {
                return Err(Error::InvalidData("erofs missing CBLKCNT"));
            }
            match (big, p.cblks) {
                (true, Some(c)) => u64::from(c) * blksz,
                _ => blksz,
            }
        }
        _ => return Err(Error::InvalidData("erofs bad lcluster type")),
    };
    check_extent_size(plen, llen)?;
    let pa = p
        .pblk
        .checked_mul(blksz)
        .ok_or(Error::InvalidData("erofs pcluster offset overflow"))?;
    let pa = usize::try_from(pa).map_err(|_| Error::InvalidData("erofs pcluster overflow"))?;
    if p.htype == LCLUSTER_PLAIN {
        return emit_raw(
            img,
            out,
            p.la,
            pa as u64,
            plen,
            llen,
            zm.advise & ADVISE_INTERLACED_PCLUSTER != 0,
        );
    }
    let alg = if p.htype == LCLUSTER_HEAD2 {
        zm.algos[1]
    } else {
        zm.algos[0]
    };
    if img.avail_compr_algs & (1u16 << alg) == 0 {
        return Err(Error::InvalidData("erofs inconsistent algorithmtype"));
    }
    let la = usize::try_from(p.la).map_err(|_| Error::InvalidData("erofs extent offset"))?;
    let ll = llen as usize;
    if la + ll > out.len() {
        return Err(Error::InvalidData("erofs extent out of range"));
    }
    // The compressed stream may be shorter than `plen`; trailing
    // bytes belong to the following pcluster and are ignored by the
    // size-bounded decoders. Clamp at the image end.
    let end_off = pa.saturating_add(plen as usize).min(img.data.len());
    let region = img
        .data
        .get(pa..end_off)
        .ok_or(Error::InvalidData("erofs pcluster out of range"))?;
    let data = inflate(img, alg, region, ll)?;
    out[la..la + ll].copy_from_slice(&data);
    Ok(())
}

/// Sequential pass over the index layouts (a specialised whole-file
/// equivalent of kernel `z_erofs_do_map_blocks`).
fn read_indexed(img: &Img<'_>, zm: &ZMap, size: u64) -> Result<Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; size as usize];
    let lsz = 1u64 << zm.lclusterbits;
    let mut pend: Option<Pend> = None;
    for lcn in 0..zm.totalidx as u64 {
        match load_index(img, zm, lcn)? {
            LcIndex::NonHead { cblkcnt } => {
                let Some(p) = pend.as_mut() else {
                    return Err(Error::InvalidData("erofs nonhead w/o head"));
                };
                if lcn != p.lcn + 1 {
                    continue;
                }
                match cblkcnt {
                    Some(c) => {
                        if p.cblks.is_some() {
                            return Err(Error::InvalidData("erofs duplicate CBLKCNT"));
                        }
                        p.cblks = Some(c);
                    }
                    None => {
                        // Under the big-pcluster advise the first
                        // NONHEAD after a head must carry CBLKCNT
                        // (BIG_PCLUSTER_2 also covers PLAIN heads).
                        let big = if p.htype == LCLUSTER_HEAD1 {
                            zm.advise & ADVISE_BIG_PCLUSTER_1 != 0
                        } else {
                            zm.advise & ADVISE_BIG_PCLUSTER_2 != 0
                        };
                        if big {
                            p.missing_cblkcnt = true;
                        }
                    }
                }
            }
            LcIndex::Head {
                htype,
                clusterofs,
                pblk,
                partial,
                hole,
            } => {
                if partial && (htype == LCLUSTER_PLAIN || hole) {
                    return Err(Error::InvalidData("erofs partial ref on raw/hole"));
                }
                let la = lcn * lsz + clusterofs;
                // erofs-utils appends a terminator index (a PLAIN
                // entry at `i_size`) to mark the tail of the last
                // pcluster; it carries no data. Anything at or past
                // the inode size ends the extent list.
                if la >= size {
                    if let Some(p) = pend.take() {
                        emit(img, &mut out, zm, p, size)?;
                    }
                    return Ok(out);
                }
                if let Some(p) = pend.take() {
                    emit(img, &mut out, zm, p, la)?;
                }
                pend = Some(Pend {
                    la,
                    lcn,
                    htype,
                    pblk,
                    hole,
                    cblks: None,
                    missing_cblkcnt: false,
                });
            }
        }
    }
    if let Some(p) = pend.take() {
        emit(img, &mut out, zm, p, size)?;
    }
    Ok(out)
}

/// Apply one `z_erofs_extent` record covering logical `[la, lend)`.
#[allow(clippy::too_many_arguments)]
fn apply_extent(
    img: &Img<'_>,
    out: &mut [u8],
    interlaced_advise: bool,
    la: u64,
    lend: u64,
    pa: u64,
    plen_raw: u32,
) -> Result<(), Error> {
    if lend <= la || la >= out.len() as u64 {
        return Err(Error::InvalidData("erofs extent out of order"));
    }
    let llen = lend.min(out.len() as u64) - la;
    let plen = u64::from(plen_raw & EXTENT_PLEN_MASK);
    let fmt = (plen_raw >> EXTENT_PLEN_FMT_BIT) & 0xf;
    // PARTIAL_REF is only a decompression bound hint for shared
    // pclusters; it is meaningless on raw extents and on holes.
    if plen_raw & EXTENT_PLEN_PARTIAL != 0 && fmt == 0 {
        return Err(Error::InvalidData("erofs partial ref on raw extent"));
    }
    check_extent_size(plen, llen)?;
    if plen == 0 {
        // Unmapped range: reads as zeros (`out` is pre-zeroed).
        return Ok(());
    }
    if fmt == 0 {
        // Raw extent: SHIFTED or INTERLACED placement.
        let interlaced = interlaced_advise && (pa | plen) & (img.blksz as u64 - 1) == 0;
        return emit_raw(img, out, la, pa, plen, llen, interlaced);
    }
    let alg = (fmt - 1) as u8;
    if alg >= ALG_MAX {
        return Err(Error::Unsupported("erofs unknown extent algorithm"));
    }
    if img.avail_compr_algs & (1u16 << alg) == 0 {
        return Err(Error::InvalidData("erofs inconsistent algorithmtype"));
    }
    let pa_us = usize::try_from(pa).map_err(|_| Error::InvalidData("erofs extent offset"))?;
    let la_us = usize::try_from(la).map_err(|_| Error::InvalidData("erofs extent offset"))?;
    let ll = llen as usize;
    if la_us + ll > out.len() {
        return Err(Error::InvalidData("erofs extent out of range"));
    }
    let region = img
        .data
        .get(pa_us..pa_us + plen as usize)
        .ok_or(Error::InvalidData("erofs extent out of range"))?;
    let data = inflate(img, alg, region, ll)?;
    out[la_us..la_us + ll].copy_from_slice(&data);
    Ok(())
}

/// `Z_EROFS_ADVISE_EXTENTS` layout (kernel `z_erofs_map_blocks_ext`):
/// a sequence of `z_erofs_extent` records after the map header.
fn read_extents(
    img: &Img<'_>,
    zm: &ZMap,
    h: &[u8],
    hpos: usize,
    size: u64,
) -> Result<Vec<u8>, Error> {
    let recsz = 4usize << ((zm.advise >> 1) & 3);
    let mut out = alloc::vec![0u8; size as usize];
    let interlaced = zm.advise & ADVISE_INTERLACED_PCLUSTER != 0;
    let mut pos = (hpos + 8).div_ceil(recsz) * recsz;
    let lsz = 1u64 << zm.lclusterbits;
    if recsz <= 8 {
        // Fixed `1 << lclusterbits` extents; record i covers logical
        // `[i << lbits, min((i+1) << lbits, size))`.
        let nrec = size.div_ceil(lsz);
        let mut pa_acc = 0u64;
        if recsz == 4 {
            let base = img.data.get(pos..pos + 8).ok_or(Error::UnexpectedEof)?;
            pa_acc = u64le(base, 0);
            pos += 8;
        }
        for i in 0..nrec {
            let rec = img.data.get(pos..pos + recsz).ok_or(Error::UnexpectedEof)?;
            pos += recsz;
            let plen_raw = u32le(rec, 0);
            let pa = if recsz == 4 {
                let p = pa_acc;
                pa_acc += u64::from(plen_raw & EXTENT_PLEN_MASK);
                p
            } else {
                u64::from(u32le(rec, 4))
            };
            apply_extent(
                img,
                &mut out,
                interlaced,
                i * lsz,
                (i + 1) * lsz,
                pa,
                plen_raw,
            )?;
        }
        return Ok(out);
    }
    // Variable-length extents with explicit lstart (recsz 16 or 32).
    let nrec = u64::from(u32le(h, 0)) | (u64::from(u16le(h, 6)) << 32);
    let mut pend: Option<(u64, u64, u32)> = None; // (lstart, pa, plen_raw)
    for i in 0..=nrec {
        let (lstart, pa, plen_raw) = if i < nrec {
            let rec = img.data.get(pos..pos + recsz).ok_or(Error::UnexpectedEof)?;
            pos += recsz;
            let plen_raw = u32le(rec, 0);
            let pa = u64::from(u32le(rec, 4)) | (u64::from(u32le(rec, 8)) << 32);
            let lstart = u64::from(u32le(rec, 12))
                | if recsz > 16 {
                    u64::from(u32le(rec, 16)) << 32
                } else {
                    0
                };
            (lstart, pa, plen_raw)
        } else {
            (size, 0, 0)
        };
        if let Some((la, epa, eplen)) = pend.take() {
            apply_extent(img, &mut out, interlaced, la, lstart.min(size), epa, eplen)?;
        }
        if i < nrec {
            pend = Some((lstart, pa, plen_raw));
        }
    }
    Ok(out)
}

/// Decode the data of a `COMPRESSED_FULL` or `COMPRESSED_COMPACT`
/// inode.
pub(crate) fn read_compressed(
    img: &Img<'_>,
    ino: &Inode,
    ino_off: usize,
) -> Result<Vec<u8>, Error> {
    if ino.size == 0 {
        return Ok(Vec::new());
    }
    let _ = usize::try_from(ino.size)
        .map_err(|_| Error::Unsupported("erofs file larger than memory"))?;
    let bbits = img.blksz.trailing_zeros();
    // The map header sits after the inode core and xattr ibody,
    // 8-byte aligned (Z_EROFS_FULL_INDEX_ALIGN).
    let hpos = ino_off
        .checked_add(align8(ino.isize + ino.xattr_isize))
        .ok_or(Error::InvalidData("erofs map header overflow"))?;
    let h = img.data.get(hpos..hpos + 8).ok_or(Error::UnexpectedEof)?;
    if h[7] >> 7 != 0 {
        // Z_EROFS_FRAGMENT_INODE_BIT: the file lives inside the
        // packed inode entirely.
        return Err(Error::Unsupported("erofs packed-inode fragment"));
    }
    let advise = u16le(h, 4);
    if advise & (ADVISE_INLINE_PCLUSTER | ADVISE_FRAGMENT_PCLUSTER) != 0 {
        return Err(Error::Unsupported("erofs tailpacked/fragment inode"));
    }
    let mut zm = ZMap {
        advise,
        algos: [h[6] & 0xf, h[6] >> 4],
        lclusterbits: bbits + u32::from(h[7] & 0xf),
        index_base: hpos + 8,
        totalidx: ino.size.div_ceil(1u64 << (bbits + u32::from(h[7] & 0xf))) as usize,
        c4b_init: usize::MAX,
        c2b: 0,
    };
    // In the EXTENTS layout advise bits 1-2 encode the record size,
    // so the big-pcluster sanity check applies to index layouts only.
    let extents = ino.datalayout == DATALAYOUT_COMPRESSED_FULL && advise & ADVISE_EXTENTS != 0;
    if !extents
        && advise & (ADVISE_BIG_PCLUSTER_1 | ADVISE_BIG_PCLUSTER_2) != 0
        && !img.big_pcluster
    {
        return Err(Error::InvalidData("erofs big pcluster w/o sb feature"));
    }
    match ino.datalayout {
        DATALAYOUT_COMPRESSED_FULL => {
            if extents {
                return read_extents(img, &zm, h, hpos, ino.size);
            }
            if zm.algos[0] >= ALG_MAX || zm.algos[1] >= ALG_MAX {
                return Err(Error::Unsupported("erofs unknown HEAD algorithm"));
            }
            // Z_EROFS_FULL_INDEX_START: a reserved 8-byte slot sits
            // between the map header and the 8-byte index table.
            zm.index_base += 8;
            read_indexed(img, &zm, ino.size)
        }
        DATALAYOUT_COMPRESSED_COMPACT => {
            if zm.algos[0] >= ALG_MAX || zm.algos[1] >= ALG_MAX {
                return Err(Error::Unsupported("erofs unknown HEAD algorithm"));
            }
            // The compact format requires consistent big-pcluster
            // advise on both head types (kernel zmap.c sanity check).
            let b1 = advise & ADVISE_BIG_PCLUSTER_1 != 0;
            let b2 = advise & ADVISE_BIG_PCLUSTER_2 != 0;
            if b1 != b2 {
                return Err(Error::InvalidData("erofs inconsistent big pcluster"));
            }
            let ebase = zm.index_base;
            let c4b = (32 - ebase % 32) / 4;
            zm.c4b_init = if c4b == 8 { 0 } else { c4b };
            zm.c2b = if advise & ADVISE_COMPACTED_2B != 0 && zm.c4b_init < zm.totalidx {
                (zm.totalidx - zm.c4b_init) / 16 * 16
            } else {
                0
            };
            read_indexed(img, &zm, ino.size)
        }
        _ => Err(Error::Unsupported("erofs compressed inode (z_erofs)")),
    }
}
