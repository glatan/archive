//! ZPAQ decoding (public API).
//!
//! Decodes canonical upstream ZPAQ streams: each block is located by
//! the 13-byte locator tag followed by `zPQ`, a format-level byte
//! (`1`/`2`), the type byte `1`, and a serialized ZPAQL header.
//! Segments carry `filename`/`comment` metadata, an arithmetic-coded
//! payload prefixed by a postprocessor selector (`0` = PASS, `1` =
//! PROG with an embedded PCOMP program), and a `253`/`254` checksum
//! trailer.  Blocks are scanned sequentially so concatenated blocks —
//! the upstream journaling layout — decode in order.
//!
//! # Examples
//!
//! ```
//! use archive::compress::zpaq::{decode, encode};
//!
//! let data = b"Hello, ZPAQ!";
//! let compressed = encode::encode(data, 1);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::sha1::sha1;

use super::arithmetic::ArithDecoder;
use super::encode::ZPAQ_TAG;
use super::predictor::Predictor;
use super::zpaql::Zpaql;

/// Parsed ZPAQ block header (ZPAQL header plus position of the first
/// segment marker).
pub(crate) struct ParsedBlockHeader {
    /// The parsed header; doubles as the VM/predictor template.
    pub(crate) zpaql: Zpaql,
    /// Wire level byte (`1` modeled-only, `2` allows unmodeled).
    pub(crate) level: u8,
    /// Offset in the input of the byte after the header.
    pub(crate) next_pos: usize,
}

/// One decoded segment.
pub(crate) struct DecodedSegment {
    /// Raw filename bytes (NUL-terminated on the wire).
    pub(crate) filename: Vec<u8>,
    /// Raw comment bytes.
    pub(crate) comment: Vec<u8>,
    /// Postprocessed (final) segment data.
    pub(crate) data: Vec<u8>,
}

/// Rolling-hash scan for the 16-byte `tag + "zPQ"` block locator,
/// upstream `Decompresser::findBlock`.  Returns the offset right after
/// `"zPQ"` on match.
fn find_block(input: &[u8], start: usize) -> Option<usize> {
    let mut h1 = 0x3D49_B113u32;
    let mut h2 = 0x29EB_7F93u32;
    let mut h3 = 0x2614_BE13u32;
    let mut h4 = 0x3828_EB13u32;
    for (i, &b) in input.iter().enumerate().skip(start) {
        let c = u32::from(b);
        h1 = h1.wrapping_mul(12).wrapping_add(c);
        h2 = h2.wrapping_mul(20).wrapping_add(c);
        h3 = h3.wrapping_mul(28).wrapping_add(c);
        h4 = h4.wrapping_mul(44).wrapping_add(c);
        if h1 == 0xB16B_88F1 && h2 == 0xFF53_76F1 && h3 == 0x72AC_5BF1 && h4 == 0x2F90_9AF1 {
            return Some(i + 1);
        }
    }
    // The locator is a fixed 16-byte string; a plain substring scan
    // yields identical results without depending on the hash.  Keep
    // the hash above as the primary check (upstream behavior) and fall
    // through here only when it did not fire.
    let mut needle = Vec::with_capacity(16);
    needle.extend_from_slice(&ZPAQ_TAG);
    needle.extend_from_slice(b"zPQ");
    input[start..]
        .windows(16)
        .position(|w| w == needle.as_slice())
        .map(|p| start + p + 16)
}

/// Scan for a block header starting the search at `start`.
/// Returns `None` when no further block locator exists.
pub(crate) fn parse_block_header_at(
    input: &[u8],
    start: usize,
) -> Result<Option<ParsedBlockHeader>, Error> {
    let Some(mut pos) = find_block(input, start) else {
        return Ok(None);
    };
    if pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    let level = input[pos];
    pos += 1;
    if level != 1 && level != 2 {
        return Err(Error::InvalidData("zpaq: unsupported level"));
    }
    if pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    if input[pos] != 1 {
        return Err(Error::InvalidData("zpaq: unsupported ZPAQL type"));
    }
    pos += 1;
    let mut zpaql = Zpaql::new();
    zpaql.read(input, &mut pos)?;
    if level == 1 && zpaql.component_count() == 0 {
        return Err(Error::InvalidData(
            "zpaq: level 1 requires at least 1 component",
        ));
    }
    Ok(Some(ParsedBlockHeader {
        zpaql,
        level,
        next_pos: pos,
    }))
}

/// Find and parse the first block header in `input`.
pub(crate) fn parse_block_header(input: &[u8]) -> Result<ParsedBlockHeader, Error> {
    parse_block_header_at(input, 0)?.ok_or(Error::InvalidData("zpaq: no block locator found"))
}

/// Postprocessor state machine, upstream `PostProcessor`.
///
/// At the start of every block's first segment the arithmetic-coded
/// prefix is `0` (PASS) or `1 psize(2) pcomp` (PROG).  With PASS the
/// decompressed bytes are output verbatim; with PROG each decoded byte
/// is fed to the PCOMP ZPAQL program and `OUT` bytes form the output.
/// The loaded PCOMP program persists for the rest of the block.
struct PostProcessor {
    /// Upstream state: 0=init, 1=PASS, 2..4=loading PROG, 5=PROG.
    state: u32,
    /// PCOMP byte count while loading.
    psize: usize,
    /// PCOMP bytes while loading.
    prog: Vec<u8>,
    /// `ph`/`pm` header fields of the block (PCOMP memory sizes).
    ph: u8,
    pm: u8,
    /// PCOMP VM (state 5) — cleared/pass-through for PASS.
    z: Zpaql,
    /// Postprocessed output pending collection.
    out: Vec<u8>,
}

impl PostProcessor {
    fn new() -> Self {
        Self {
            state: 0,
            psize: 0,
            prog: Vec::new(),
            ph: 0,
            pm: 0,
            z: Zpaql::new(),
            out: Vec::new(),
        }
    }

    /// Upstream `PostProcessor::init(ph, pm)` — called once per block.
    fn init(&mut self, ph: u8, pm: u8) {
        self.state = 0;
        self.psize = 0;
        self.prog.clear();
        self.ph = ph;
        self.pm = pm;
        self.z = Zpaql::new();
        self.out.clear();
    }

    /// Process one decoded byte (`-1` = end of segment), upstream
    /// `PostProcessor::write`.
    fn write(&mut self, c: i32) -> Result<(), Error> {
        match self.state {
            0 => {
                if c < 0 {
                    return Err(Error::InvalidData("zpaq: unexpected end of segment"));
                }
                self.state = (c + 1) as u32; // 1=PASS, 2=PROG
                if self.state > 2 {
                    return Err(Error::InvalidData("zpaq: unknown postprocessing type"));
                }
            }
            1 => {
                if c >= 0 {
                    self.out.push(c as u8);
                }
            }
            2 => {
                if c < 0 {
                    return Err(Error::InvalidData("zpaq: unexpected end of segment"));
                }
                self.psize = c as usize;
                self.state = 3;
            }
            3 => {
                if c < 0 {
                    return Err(Error::InvalidData("zpaq: unexpected end of segment"));
                }
                self.psize += (c as usize) << 8;
                if self.psize < 1 {
                    return Err(Error::InvalidData("zpaq: empty PCOMP"));
                }
                self.prog.clear();
                self.prog
                    .try_reserve(self.psize)
                    .map_err(|_| Error::InvalidData("zpaq: PCOMP allocation failed"))?;
                self.state = 4;
            }
            4 => {
                if c < 0 {
                    return Err(Error::InvalidData("zpaq: unexpected end of segment"));
                }
                self.prog.push(c as u8);
                if self.prog.len() == self.psize {
                    self.z = Zpaql::set_pcomp_header(self.ph, self.pm, &self.prog)?;
                    self.z.initp()?;
                    self.state = 5;
                }
            }
            _ => {
                // PROG loaded: run the PCOMP program on the decoded
                // byte; -1 arrives as 0xFFFFFFFF at end of segment.
                let input = if c < 0 { u32::MAX } else { c as u32 };
                self.z.run(input)?;
                let produced = self.z.take_output();
                self.out.extend_from_slice(&produced);
            }
        }
        Ok(())
    }

    fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }
}

/// Streaming decoder for the segments of one block.
///
/// Mirrors upstream `Decompresser`: the arithmetic decoder and the
/// predictor initialize once per block and share state across all its
/// segments, so a `BlockDecoder` must be driven to the block end (a
/// `None` return) before its position is meaningful for the next block.
pub(crate) struct BlockDecoder<'a> {
    dec: ArithDecoder<'a>,
    pred: Predictor,
    pp: PostProcessor,
    /// `ph`/`pm` for `PostProcessor::init`.
    ph: u8,
    pm: u8,
    /// Whether `dec.init`/`pp.init` still needs to run (first segment).
    first_seg: bool,
    /// Absolute offset in the input where `dec` started reading.
    base: usize,
    /// Output cap applied to this block's segment data
    /// (`usize::MAX` = unlimited).
    max_output: usize,
    /// Total postprocessed bytes emitted by this block so far.
    emitted: usize,
    /// Absolute offset just past the last consumed byte.
    last_pos: usize,
}

impl<'a> BlockDecoder<'a> {
    /// Bind a decoder to `input` positioned at `base` (the value of
    /// [`ParsedBlockHeader::next_pos`]).
    pub(crate) fn new(
        input: &'a [u8],
        header: &ParsedBlockHeader,
        max_output: usize,
    ) -> Result<Self, Error> {
        let pred = Predictor::new(header.zpaql.clone())?;
        Ok(Self {
            dec: ArithDecoder::new(&input[header.next_pos..]),
            pred,
            pp: PostProcessor::new(),
            ph: header.zpaql.header_at(4),
            pm: header.zpaql.header_at(5),
            first_seg: true,
            base: header.next_pos,
            max_output,
            emitted: 0,
            last_pos: header.next_pos,
        })
    }

    /// Absolute input offset just past the last consumed byte — the
    /// position where the next block scan should start after this
    /// block decoder returned `None`.
    pub(crate) fn end_pos(&self) -> usize {
        self.last_pos
    }

    /// Upstream `Decoder::decompress`: next postprocessed-input byte,
    /// or `-1` at end of the segment's coded data.
    fn decompress_byte(&mut self) -> Result<i32, Error> {
        if self.pred.is_modeled() {
            if self.dec.curr == 0 {
                for _ in 0..4 {
                    let c = self.dec.get();
                    if c < 0 {
                        return Err(Error::InvalidData("zpaq: truncated arithmetic stream"));
                    }
                    self.dec.curr = (self.dec.curr << 8) | (c as u32);
                }
            }
            if self.dec.decode(0)? != 0 {
                if self.dec.curr != 0 {
                    return Err(Error::InvalidData("zpaq: corrupted end of segment"));
                }
                return Ok(-1);
            }
            let mut c: u32 = 1;
            while c < 256 {
                let p = (self.pred.predict() * 2 + 1) as u32;
                let y = self.dec.decode(p)?;
                c = c + c + y;
                self.pred.update(y)?;
            }
            Ok((c - 256) as i32)
        } else {
            if self.dec.curr == 0 {
                for _ in 0..4 {
                    let c = self.dec.get();
                    if c < 0 {
                        return Err(Error::InvalidData("zpaq: truncated stored stream"));
                    }
                    self.dec.curr = (self.dec.curr << 8) | (c as u32);
                }
                if self.dec.curr == 0 {
                    return Ok(-1);
                }
            }
            self.dec.curr -= 1;
            let c = self.dec.get();
            if c < 0 {
                return Err(Error::InvalidData("zpaq: truncated stored block"));
            }
            Ok(c)
        }
    }

    /// Decode the next segment.  Returns `Ok(None)` at the end-of-block
    /// marker (`255`); `next_pos` then points just past it.
    pub(crate) fn next_segment(&mut self) -> Result<Option<DecodedSegment>, Error> {
        // FILENAME state: 1 = segment, 255 = end of block.
        let c = self.dec.get();
        if c < 0 {
            return Err(Error::UnexpectedEof);
        }
        if c == 255 {
            self.last_pos = self.base + self.dec.position();
            return Ok(None);
        }
        if c != 1 {
            return Err(Error::InvalidData("zpaq: missing segment or end of block"));
        }

        let filename = self.read_terminated()?;
        let comment = self.read_terminated()?;
        if self.dec.get() != 0 {
            return Err(Error::InvalidData("zpaq: missing reserved byte"));
        }

        // DATA state.
        if self.first_seg {
            self.dec.init(self.pred.is_modeled());
            self.pp.init(self.ph, self.pm);
            self.first_seg = false;
        }
        // Load the postprocessor (PASS flag or PROG program) — only
        // consumes bytes while the pp state machine is mid-load.
        while self.pp.state & 3 != 1 {
            let c = self.decompress_byte()?;
            self.pp.write(c)?;
        }
        let mut data = Vec::new();
        loop {
            let c = self.decompress_byte()?;
            self.pp.write(c)?;
            let produced = self.pp.take_output();
            if self.max_output != usize::MAX
                && produced.len() > self.max_output - self.emitted.min(self.max_output)
            {
                return Err(Error::OutputLimitExceeded {
                    limit: self.max_output,
                });
            }
            self.emitted += produced.len();
            data.extend_from_slice(&produced);
            if c < 0 {
                break;
            }
        }

        // SEGEND: checksum marker.
        let marker = self.dec.get();
        let sha1sum = match marker {
            254 => None,
            253 => {
                let mut s = [0u8; 20];
                for b in &mut s {
                    let c = self.dec.get();
                    if c < 0 {
                        return Err(Error::UnexpectedEof);
                    }
                    *b = c as u8;
                }
                Some(s)
            }
            -1 => return Err(Error::UnexpectedEof),
            _ => return Err(Error::InvalidData("zpaq: missing end of segment marker")),
        };
        if let Some(expected) = sha1sum {
            let actual = sha1(&data);
            if actual != expected {
                return Err(Error::InvalidData("zpaq: segment SHA-1 mismatch"));
            }
        }

        self.last_pos = self.base + self.dec.position();
        Ok(Some(DecodedSegment {
            filename,
            comment,
            data,
        }))
    }

    fn read_terminated(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        loop {
            let c = self.dec.get();
            if c < 0 {
                return Err(Error::UnexpectedEof);
            }
            if c == 0 {
                return Ok(out);
            }
            out.push(c as u8);
        }
    }
}

/// Decompress ZPAQ format data.
///
/// Scans every block in `input` and concatenates all segment payloads,
/// matching upstream `libzpaq::decompress` behavior. Input without a
/// block locator yields empty output, as upstream keeps scanning until
/// end of input.
///
/// # Errors
///
/// Returns an error if a located block or its segments are malformed.
///
/// # Examples
///
/// ```
/// use archive::compress::zpaq::{decode, encode};
///
/// let data = b"Hello, ZPAQ!";
/// let compressed = encode::encode(data, 1);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, 0)
}

/// Decode with a maximum output size limit.
///
/// Returns [`Error::OutputLimitExceeded`] if the decompressed output
/// would exceed `max_output` bytes. A `max_output` of 0 means
/// unlimited.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut start = 0;
    while let Some(header) = parse_block_header_at(input, start)? {
        let remaining = if max_output == 0 {
            usize::MAX
        } else {
            max_output.saturating_sub(output.len())
        };
        let mut block = BlockDecoder::new(input, &header, remaining)?;
        while let Some(segment) = block.next_segment()? {
            output.extend_from_slice(&segment.data);
        }
        if max_output != 0 && output.len() > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        start = block.end_pos();
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    /// Dev-only interop helper: writes our encoder output under /tmp
    /// for the upstream oracle to decode. Run with ZPAQ_DUMP=1.
    #[cfg(feature = "std")]
    #[test]
    fn dump_rust_encoded_fixture() {
        if std::env::var_os("ZPAQ_DUMP").is_none() {
            return;
        }
        let input = b"Hello, ZPAQ! The quick brown fox jumps over the lazy dog. 0123456789";
        for level in 1..=3u32 {
            let enc = crate::compress::zpaq::encode::encode(input, level);
            std::fs::write(format!("/tmp/zpaq_rust_l{level}.zpaq"), &enc).unwrap();
        }
    }

    /// Upstream libzpaq-generated fixtures committed under
    /// tests/fixtures/zpaq/ (see tests/fixtures/README.md).
    /// hello.upstream-pcomp-inc.bin is upstream's own decoded output
    /// of the non-identity PCOMP stream, kept because the transform
    /// and the EOS run(-1) emission are upstream-defined behavior.
    #[test]
    fn decode_upstream_fixtures() {
        let hello: &[u8] = include_bytes!("../../../tests/fixtures/zpaq/hello.txt");
        // Modeled streams at all three built-in upstream levels.
        for name in ["l1", "l2", "l3"] {
            let enc =
                match name {
                    "l1" => include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-l1.zpaq")
                        .as_slice(),
                    "l2" => include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-l2.zpaq")
                        .as_slice(),
                    _ => include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-l3.zpaq")
                        .as_slice(),
                };
            let d = decode(enc).unwrap_or_else(|e| panic!("level {name}: {e}"));
            assert_eq!(d, hello, "level {name}");
        }
        // Empty and binary payloads produced by upstream.
        let enc = include_bytes!("../../../tests/fixtures/zpaq/empty.upstream-l1.zpaq");
        assert_eq!(decode(enc).unwrap(), b"");
        let enc = include_bytes!("../../../tests/fixtures/zpaq/bin.upstream-l1.zpaq");
        let want = include_bytes!("../../../tests/fixtures/zpaq/bin.bin");
        assert_eq!(decode(enc).unwrap(), want);
        // Stored (unmodeled, n=0) stream produced by upstream.
        let enc = include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-stored.zpaq");
        assert_eq!(decode(enc).unwrap(), hello);
        // PROG segment: upstream stream carrying an identity PCOMP
        // program (OUT; HALT). Upstream's decoder emits a trailing
        // 0xFF because run(-1) executes OUT once more at EOS, so the
        // output must match byte-for-byte including it.
        let enc = include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-pcomp-id.zpaq");
        let mut want = hello.to_vec();
        want.push(0xFF);
        assert_eq!(decode(enc).unwrap(), want);
        // Non-identity PCOMP (a++; out; halt): each byte +1, and the
        // EOS run(-1) emits a wrapped 0x00. The expected bytes are
        // upstream's own decode output.
        let enc = include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-pcomp-inc.zpaq");
        let want = include_bytes!("../../../tests/fixtures/zpaq/hello.upstream-pcomp-inc.bin");
        assert_eq!(decode(enc).unwrap(), want);
    }

    /// Stored-mode roundtrip: an n=0 CustomModel produces an
    /// unmodeled stream that must decode to the original input.
    #[test]
    fn stored_mode_roundtrip() {
        let input = include_bytes!("../../../tests/fixtures/zpaq/hello.txt");
        let model = crate::compress::zpaq::encode::CustomModel::new(2, 0, 0, vec![0], vec![56])
            .expect("stored model");
        let enc = crate::compress::zpaq::encode::encode_with_model(input, &model).unwrap();
        assert_eq!(decode(&enc).unwrap(), input);
    }

    /// A CustomModel exercising the CM and AVG predictor components,
    /// which the built-in level 1-3 models do not use.
    #[test]
    fn custom_model_cm_avg_roundtrip() {
        let input = include_bytes!("../../../tests/fixtures/zpaq/bin.bin");
        // n=3: CONST(128), CM(sizebits=4, limit=100), AVG(j=0, k=1, wt=0).
        let comp = vec![3, 1, 128, 2, 4, 100, 5, 0, 1, 0];
        let model = crate::compress::zpaq::encode::CustomModel::new(1, 8, 8, comp, vec![56])
            .expect("cm/avg model");
        let enc = crate::compress::zpaq::encode::encode_with_model(input, &model).unwrap();
        assert_eq!(decode(&enc).unwrap(), input);
    }

    /// Dev-only interop helper: writes edge-case encoder output plus
    /// a multi-segment archive under /tmp for the upstream oracle.
    /// Run with ZPAQ_DUMP=1.
    #[cfg(feature = "std")]
    #[test]
    fn dump_rust_edge_fixtures() {
        if std::env::var_os("ZPAQ_DUMP").is_none() {
            return;
        }
        // Empty input
        std::fs::write(
            "/tmp/zpaq_rust_empty.zpaq",
            crate::compress::zpaq::encode::encode(b"", 2),
        )
        .unwrap();
        // Binary data incl. all byte values
        let mut bin = Vec::new();
        for i in 0..4096u32 {
            bin.push((i * 31 + 7) as u8);
        }
        bin.extend_from_slice(&[0u8; 512]);
        for i in 0..256u32 {
            bin.push(i as u8);
        }
        std::fs::write(
            "/tmp/zpaq_rust_bin.zpaq",
            crate::compress::zpaq::encode::encode(&bin, 2),
        )
        .unwrap();
        std::fs::write("/tmp/zpaq_plain_bin.bin", &bin).unwrap();
        // Larger repetitive text
        let mut big = Vec::new();
        for i in 0..2000u32 {
            big.extend_from_slice(
                format!(
                    "line {i}: the quick brown fox
"
                )
                .as_bytes(),
            );
        }
        std::fs::write(
            "/tmp/zpaq_rust_big.zpaq",
            crate::compress::zpaq::encode::encode(&big, 3),
        )
        .unwrap();
        std::fs::write("/tmp/zpaq_plain_big.txt", &big).unwrap();
        // Multi-segment archive (2 entries)
        let mut enc = crate::archive::zpaq::encode::ZpaqEncoder::new(2);
        enc.add_file("a.txt", b"alpha payload");
        enc.add_file_with_comment("b.txt", "note", b"beta payload!");
        std::fs::write("/tmp/zpaq_rust_multi.zpaq", enc.finish().unwrap()).unwrap();
    }

    /// Malformed/truncated inputs must fail cleanly; garbage without a
    /// block locator yields empty output, matching upstream
    /// `findBlock` scanning behavior.
    #[test]
    fn decode_rejects_malformed_streams() {
        let good = crate::compress::zpaq::encode::encode(b"payload", 1);
        // No block locator -> empty output (upstream scans for blocks).
        assert_eq!(decode(b"not a zpaq stream").unwrap(), b"");
        // Truncated right after the 16-byte locator -> error.
        assert!(decode(&good[..20]).is_err());
        // Truncated inside the coded payload -> error.
        assert!(decode(&good[..good.len() - 3]).is_err());
        // Level byte must be 1 (modeled) or 2 (unmodeled), as upstream.
        let mut bad = good.clone();
        bad[16] = 7;
        assert!(matches!(decode(&bad), Err(Error::InvalidData(_))));
        // ZPAQL type byte must be 1.
        let mut bad = good.clone();
        bad[17] = 9;
        assert!(matches!(decode(&bad), Err(Error::InvalidData(_))));
        // Corrupting a SHA-1 byte (last 21 bytes: 253 + 20-byte digest)
        // must produce a checksum mismatch.
        let mut bad = good.clone();
        let n = bad.len();
        assert_eq!(bad[n - 1], 255);
        bad[n - 3] ^= 0xFF;
        assert!(matches!(decode(&bad), Err(Error::InvalidData(_))));
    }

    /// `decode_bounded` must enforce the output limit.
    #[test]
    fn decode_bounded_enforces_limit() {
        let enc = crate::compress::zpaq::encode::encode(
            b"a payload long enough to exceed a small limit",
            1,
        );
        assert!(matches!(
            decode_bounded(&enc, 4),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(
            decode_bounded(&enc, 1024).unwrap(),
            b"a payload long enough to exceed a small limit"
        );
    }

    /// `CustomModel` rejects structurally invalid headers up front.
    #[test]
    fn custom_model_rejects_invalid_headers() {
        use crate::compress::zpaq::encode::CustomModel;
        // level 1 requires at least one component.
        assert!(CustomModel::new(1, 0, 0, vec![0], vec![56]).is_err());
        // level byte must be 1 or 2.
        assert!(CustomModel::new(3, 0, 0, vec![0], vec![56]).is_err());
        // hh/hm must be <= 32.
        assert!(CustomModel::new(2, 33, 0, vec![0], vec![56]).is_err());
        // n=1 declared but no component record present.
        assert!(CustomModel::new(2, 0, 0, vec![1], vec![56]).is_err());
        // unknown component type.
        assert!(CustomModel::new(2, 0, 0, vec![1, 42], vec![56]).is_err());
        // truncated component record (CM needs 3 bytes total).
        assert!(CustomModel::new(2, 0, 0, vec![1, 2, 8], vec![56]).is_err());
    }

    #[test]
    fn builtin_levels_roundtrip() {
        for level in 1..=3u32 {
            let input = b"Hello, ZPAQ!";
            let enc = crate::compress::zpaq::encode::encode(input, level);
            match decode(&enc) {
                Ok(d) => assert_eq!(d, input, "level {level}"),
                Err(e) => panic!("level {level}: {e}"),
            }
        }
    }
}
