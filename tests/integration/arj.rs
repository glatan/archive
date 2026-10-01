// ============================================================
// ARJ container tests (method 0 / stored only)
// ============================================================

fn arj_fixture(name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = archive::archive::arj::encode::ArjEncoder::new();
    enc.add_file(name, data, 0).unwrap();
    enc.finish()
}

#[test]
fn test_arj_encode_decode_roundtrip() {
    let data = b"hello arj world".repeat(8);
    let a = arj_fixture("hello.txt", &data);
    let entries = archive::archive::arj::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].data, data.as_slice());
    assert_eq!(entries[0].method, 0);
}

#[test]
fn test_arj_multi_entry_roundtrip() {
    let mut enc = archive::archive::arj::encode::ArjEncoder::new();
    enc.add_dir("sub", 0).unwrap();
    enc.add_file("sub/a.bin", &[5, 6, 7], 0).unwrap();
    enc.add_file("top.txt", b"top", 0).unwrap();
    let entries = archive::archive::arj::decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[0].is_dir);
    assert_eq!(entries[1].name, "sub/a.bin");
    assert_eq!(entries[2].data, b"top");
}

#[test]
fn test_arj_rejects_truncated() {
    let a = arj_fixture("f.txt", b"payload");
    assert!(archive::archive::arj::decode::decode(&a[..10]).is_err());
    assert!(archive::archive::arj::decode::decode(&a[..a.len() - 4]).is_err());
    // No terminator at all: decode must fail at the next signature read.
    assert!(archive::archive::arj::decode::decode(&a[..a.len() - 6]).is_err());
}

#[test]
fn test_arj_rejects_compressed_method() {
    let mut a = arj_fixture("f.txt", b"payload");
    // File header follows: sig(2)+size(2)+body+crc(4)+ext(2).
    let h1 = u16::from_le_bytes([a[2], a[3]]) as usize;
    let second = 4 + h1 + 4 + 2;
    a[second + 4 + 5] = 9; // method 9: never assigned
    let bsize = u16::from_le_bytes([a[second + 2], a[second + 3]]) as usize;
    let crc = crc32_local(&a[second + 4..second + 4 + bsize]);
    a[second + 4 + bsize..second + 8 + bsize].copy_from_slice(&crc.to_le_bytes());
    let err = archive::archive::arj::decode::decode(&a).unwrap_err();
    assert!(matches!(err, archive::error::Error::Unsupported(_)));
}

fn crc32_local(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[test]
fn test_arj_7z_list_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let data = b"arj 7z interop payload".repeat(4);
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_arj_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.arj");
    std::fs::write(&path, arj_fixture("interop.txt", &data)).unwrap();

    // 7-Zip reads ARJ: verify it can list and extract our method-0 file.
    let output = Command::new("7z").args(["l"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // 7z build without ARJ support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("interop.txt"), "7z l output: {listing}");

    let out_dir = dir.join("out");
    let output = Command::new("7z")
        .args(["x", "-y"])
        .arg(format!("-o{}", out_dir.display()))
        .arg(&path)
        .output()
        .unwrap();
    if output.status.success() {
        let extracted = std::fs::read(out_dir.join("interop.txt")).unwrap();
        assert_eq!(extracted, data.as_slice());
    }
}

// ============================================================
// Compressed methods (1-4), garbled, and multi-volume fixtures.
// Mirror encoders reproduce the wire formats; / act as
// independent oracles when installed.
// ============================================================

use archive::archive::arj::decode as arj_decode;
use std::collections::BTreeMap;

/// MSB-first bit writer for the LZH/method-4 streams.
struct BitW {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitW {
    fn new() -> Self {
        BitW {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }
    fn put(&mut self, val: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((val >> i) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

#[derive(Clone)]
enum Tok {
    Lit(u8),
    Match { len: usize, dist: usize },
}

fn simulate(tokens: &[Tok]) -> Vec<u8> {
    let mut out = Vec::new();
    for t in tokens {
        match t {
            Tok::Lit(b) => out.push(*b),
            Tok::Match { len, dist } => {
                for _ in 0..*len {
                    out.push(out[out.len() - dist]);
                }
            }
        }
    }
    out
}

/// Huffman code lengths for the given symbol frequencies (0 for
/// absent symbols). Single-symbol alphabets get length 1.
fn huffman_lens(freq: &BTreeMap<u32, u32>) -> Vec<u32> {
    use std::collections::BinaryHeap;
    let n = freq.keys().max().map(|m| *m as usize + 1).unwrap_or(0);
    let mut lens = vec![0u32; n];
    if freq.len() == 1 {
        lens[*freq.keys().next().unwrap() as usize] = 1;
        return lens;
    }
    // (negated weight for min-heap via Reverse, tie-break on id)
    let mut heap: BinaryHeap<(std::cmp::Reverse<u32>, u32)> = BinaryHeap::new();
    let mut next = 0u32;
    let mut weight: Vec<u32> = Vec::new();
    let mut leaf: Vec<Option<u32>> = Vec::new();
    for (&s, &f) in freq {
        weight.push(f);
        leaf.push(Some(s));
        heap.push((std::cmp::Reverse(f), next));
        next += 1;
    }
    let mut parent: Vec<u32> = vec![0; weight.len() * 2];
    while heap.len() > 1 {
        let (std::cmp::Reverse(fa), a) = heap.pop().unwrap();
        let (std::cmp::Reverse(fb), b) = heap.pop().unwrap();
        parent[a as usize] = next;
        parent[b as usize] = next;
        weight.push(fa + fb);
        leaf.push(None);
        heap.push((std::cmp::Reverse(fa + fb), next));
        next += 1;
    }
    for (i, lf) in leaf.iter().enumerate() {
        if let Some(s) = lf {
            let mut d = 0u32;
            let mut n = i;
            while parent[n] != 0 {
                d += 1;
                n = parent[n] as usize;
            }
            lens[*s as usize] = d.clamp(1, 16);
        }
    }
    lens
}

/// Canonical (code, len) assignment matching the decoder's builder:
/// ascending length, ascending symbol.
fn canonical_codes(lens: &[u32]) -> (Vec<(u32, u32)>, usize) {
    let max = *lens.iter().max().unwrap_or(&0);
    let mut codes = vec![(0u32, 0u32); lens.len()];
    let mut code = 0u32;
    for len in 1..=max {
        for (i, &ln) in lens.iter().enumerate() {
            if ln == len {
                codes[i] = (code, len);
                code += 1;
            }
        }
        code <<= 1;
    }
    (codes, lens.len())
}

fn emit_len(w: &mut BitW, len: u32) {
    if len < 7 {
        w.put(len, 3);
    } else {
        w.put(7, 3);
        for _ in 0..(len - 7) {
            w.put(1, 1);
        }
        w.put(0, 1);
    }
}

/// Serialize a position/meta table ( inverse):
/// -bit count, per-symbol 3-bit lengths with unary-7
/// extension, and the special-index 2-bit zero run.
fn emit_pt_lens(w: &mut BitW, lens: &[u32], width: u32, special: Option<usize>) {
    let used = lens.iter().filter(|&&l| l > 0).count();
    if used <= 1 {
        w.put(0, width);
        let sym = lens.iter().position(|&l| l > 0).unwrap_or(0);
        w.put(sym as u32, width);
        return;
    }
    w.put(lens.len() as u32, width);
    let mut n = 0usize;
    for &len in lens {
        emit_len(w, len);
        n += 1;
        if special == Some(n) {
            w.put(0, 2); // zero trailing zero-run
        }
    }
}

/// Serialize the literal/match table ( inverse): meta
/// table, 9-bit count, then each length through meta symbols
/// (0 => one zero, len => len + 2).
fn emit_c_tab(w: &mut BitW, lit_lens: &[u32]) {
    // Meta code over the distinct length values actually used
    // (len == 0 => symbol 0, otherwise symbol len + 2).
    let mut meta_freq: BTreeMap<u32, u32> = BTreeMap::new();
    for &l in lit_lens {
        *meta_freq.entry(if l == 0 { 0 } else { l + 2 }).or_insert(0) += 1;
    }
    let meta_lens = huffman_lens(&meta_freq);
    emit_pt_lens(w, &meta_lens, 5, Some(3));
    w.put(lit_lens.len() as u32, 9);
    let (meta_codes, _) = canonical_codes(&meta_lens);
    for &l in lit_lens {
        let sym = (if l == 0 { 0 } else { l + 2 }) as usize;
        let (code, len) = meta_codes[sym];
        w.put(code, len);
    }
}

/// (position symbol, extra value, extra bits) for a distance,
/// inverting the st1 offset decode (dist 1 => sym 0, dist 2 => sym 1,
/// else bits = position of highest set bit of dist - 1).
fn dist_sym(dist: usize) -> (u32, u32, u32) {
    match dist {
        1 => (0, 0, 0),
        2 => (1, 0, 0),
        _ => {
            let v = dist - 1;
            let mut b = 1u32;
            while (1usize << b) <= v {
                b += 1;
            }
            (b, (v - (1usize << (b - 1))) as u32, b - 1)
        }
    }
}

/// Encode  as one ARJ st1 block (15-bit window, 5-bit
/// distance count field).
fn encode_lzh15(tokens: &[Tok]) -> Vec<u8> {
    // Huffman lengths over actual token frequencies (complete trees).
    let mut lit_freq = BTreeMap::new();
    let mut dist_freq = BTreeMap::new();
    for t in tokens {
        match t {
            Tok::Lit(b) => *lit_freq.entry(*b as u32).or_insert(0u32) += 1,
            Tok::Match { len, dist } => {
                *lit_freq.entry(0x100 + (*len - 3) as u32).or_insert(0) += 1;
                *dist_freq.entry(dist_sym(*dist).0).or_insert(0) += 1;
            }
        }
    }
    let lit_lens = huffman_lens(&lit_freq);
    let dist_lens = huffman_lens(&dist_freq);
    let (lit_codes, _) = canonical_codes(&lit_lens);
    let (dist_codes, _) = canonical_codes(&dist_lens);

    let mut w = BitW::new();
    w.put(tokens.len() as u32, 16);
    emit_c_tab(&mut w, &lit_lens);
    emit_pt_lens(&mut w, &dist_lens, 5, None);
    for t in tokens {
        match t {
            Tok::Lit(b) => {
                let (c, n) = lit_codes[*b as usize];
                w.put(c, n);
            }
            Tok::Match { len, dist } => {
                let sym = 0x100 + (*len - 3);
                let (c, n) = lit_codes[sym];
                w.put(c, n);
                let (dsym, extra, ebits) = dist_sym(*dist);
                let (c, n) = dist_codes[dsym as usize];
                w.put(c, n);
                if ebits > 0 {
                    w.put(extra, ebits);
                }
            }
        }
    }
    w.finish()
}

/// Encode  as an ARJ method-4 stream.
fn encode_fastest(tokens: &[Tok]) -> Vec<u8> {
    let mut w = BitW::new();
    for t in tokens {
        match t {
            Tok::Lit(b) => {
                w.put(0, 1);
                w.put(*b as u32, 8);
            }
            Tok::Match { len, dist } => {
                let val = (*len - 2) as u32;
                let mut k = 0u32;
                while k < 7 && (1u32 << (k + 1)) - 1 <= val {
                    k += 1;
                }
                for _ in 0..k {
                    w.put(1, 1);
                }
                if k < 7 {
                    w.put(0, 1);
                }
                if k > 0 {
                    w.put(val - ((1u32 << k) - 1), k);
                }
                let v = (*dist - 1) as u32;
                let mut m = 0u32;
                while m < 4 && v >= 512 * ((1u32 << (m + 1)) - 1) {
                    m += 1;
                }
                for _ in 0..m {
                    w.put(1, 1);
                }
                if m < 4 {
                    w.put(0, 1);
                }
                w.put(v - 512 * ((1u32 << m) - 1), 9 + m);
            }
        }
    }
    w.finish()
}

// --- ARJ container builder (spec field order) --------------------

struct M {
    name: &'static str,
    flags: u8,
    method: u8,
    file_type: u8,
    pmod: u8,
    decoded: Vec<u8>,
    data: Vec<u8>,
}

fn member(name: &'static str, method: u8, decoded: Vec<u8>, data: Vec<u8>) -> M {
    M {
        name,
        flags: 0x10,
        method,
        file_type: 0,
        pmod: 0,
        decoded,
        data,
    }
}

fn hdr_block(body: &[u8]) -> Vec<u8> {
    let mut b = vec![0x60u8, 0xea];
    b.extend_from_slice(&(body.len() as u16).to_le_bytes());
    b.extend_from_slice(body);
    b.extend_from_slice(&crc32_local(body).to_le_bytes());
    b
}

fn main_hdr() -> Vec<u8> {
    let mut h = vec![0u8; 30];
    h[0] = 30;
    h[1] = 10;
    h[2] = 1;
    h[3] = 2; // host os = unix
    h[4] = 0x10;
    h[5] = 2; // security version
    h[6] = 2; // file type = main header
    h.extend_from_slice(b"archive");
    h.push(0);
    h.push(0);
    h
}

fn file_hdr(m: &M) -> Vec<u8> {
    let mut h = vec![0u8; 30];
    h[0] = 30;
    h[1] = 10;
    h[2] = 1;
    h[3] = 2;
    h[4] = m.flags;
    h[5] = m.method;
    h[6] = m.file_type;
    h[7] = m.pmod;
    h[12..16].copy_from_slice(&(m.data.len() as u32).to_le_bytes()); // packed
    h[16..20].copy_from_slice(&(m.decoded.len() as u32).to_le_bytes()); // original
    h[20..24].copy_from_slice(&crc32_local(&m.decoded).to_le_bytes());
    h.extend_from_slice(m.name.as_bytes());
    h.push(0);
    h.push(0);
    h
}

fn build_arj(members: &[M]) -> Vec<u8> {
    let mut out = hdr_block(&main_hdr());
    out.extend_from_slice(&[0, 0]);
    for m in members {
        out.extend_from_slice(&hdr_block(&file_hdr(m)));
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&m.data);
    }
    out.extend_from_slice(&[0x60, 0xea, 0, 0]);
    out
}

fn mix_tokens() -> Vec<Tok> {
    vec![
        Tok::Lit(b'A'),
        Tok::Lit(b'R'),
        Tok::Lit(b'J'),
        Tok::Lit(b'!'),
        Tok::Lit(b' '),
        Tok::Match { len: 5, dist: 5 },
        Tok::Lit(b'!'),
        Tok::Match { len: 3, dist: 1 },
        Tok::Match { len: 8, dist: 11 },
    ]
}

#[test]
fn test_arj_compressed_methods() {
    let mix = mix_tokens();
    let text: Vec<Tok> = b"the quick brown fox jumps over the lazy dog"
        .iter()
        .map(|&b| Tok::Lit(b))
        .collect();
    let members = [
        member("m1.bin", 1, simulate(&mix), encode_lzh15(&mix)),
        member("m2.bin", 2, simulate(&mix), encode_lzh15(&mix)),
        member("m3.bin", 3, simulate(&mix), encode_lzh15(&mix)),
        member("text.bin", 2, simulate(&text), encode_lzh15(&text)),
        member("m4.bin", 4, simulate(&mix), encode_fastest(&mix)),
    ];
    let arj = build_arj(&members);
    let entries = arj_decode::decode(&arj).unwrap();
    assert_eq!(entries.len(), 5);
    for (e, m) in entries.iter().zip(members.iter()) {
        assert_eq!(e.name, m.name);
        assert_eq!(e.method, m.method);
        assert_eq!(e.data, m.decoded, "{}: decode mismatch", m.name);
    }
}

/// Build a garbled variant of  (XOR with password+pmod),
/// wrapped as a single-member archive.
fn garbled_arj(
    name: &'static str,
    method: u8,
    decoded: &[u8],
    packed: &[u8],
    pw: &[u8],
    pmod: u8,
) -> Vec<u8> {
    let mut m = member(name, method, decoded.to_vec(), packed.to_vec());
    m.flags = 0x11; // garbled + pathsym
    m.pmod = pmod;
    m.data = packed
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ pw[i % pw.len()].wrapping_add(pmod))
        .collect();
    build_arj(&[m])
}

#[test]
fn test_arj_garbled() {
    let mix = mix_tokens();
    let packed = encode_lzh15(&mix);
    let decoded = simulate(&mix);
    let pw = b"secret";
    // Garbled compressed member: stored CRC still verifies.
    let a = garbled_arj("g.bin", 2, &decoded, &packed, pw, 0x42);
    assert!(matches!(
        arj_decode::decode(&a),
        Err(archive::error::Error::Unsupported(_))
    ));
    let e = arj_decode::decode_with_password_bytes(&a, pw).unwrap();
    assert_eq!(e[0].data, decoded);
    // Wrong password -> de-garbled stream decodes to wrong bytes or fails.
    let bad = arj_decode::decode_with_password_bytes(&a, b"wrong");
    if let Ok(bad) = bad {
        assert_ne!(bad[0].data, decoded);
    }
    // Garbled stored member too.
    let a = garbled_arj("s.bin", 0, b"plain data", b"plain data", pw, 0);
    let e = arj_decode::decode_with_password_bytes(&a, pw).unwrap();
    assert_eq!(e[0].data, b"plain data");
}

#[test]
fn test_arj_multi_volume() {
    let mix = mix_tokens();
    let packed = encode_lzh15(&mix);
    let decoded = simulate(&mix);
    let half = packed.len() / 2;

    // Volume 1: member flagged 0x04 (continued), first half of data.
    let mut m1 = member("split.bin", 2, decoded.clone(), packed[..half].to_vec());
    m1.flags = 0x14; // volume + pathsym
    let v1 = build_arj(&[m1]);
    // Volume 2: same header, flag cleared, second half.
    let m2 = member("split.bin", 2, decoded.clone(), packed[half..].to_vec());
    let v2 = build_arj(&[m2]);

    let e = arj_decode::decode_parts(&[&v1, &v2]).unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].name, "split.bin");
    assert_eq!(e[0].data, decoded);
    // Volume 1 alone is a truncated multi-volume archive.
    assert!(arj_decode::decode(&v1).is_err());
}

#[test]
fn test_arj_multi_volume_three_way() {
    // Stored file split across three volumes.
    let data: Vec<u8> = (0u8..200).map(|i| i.wrapping_mul(37)).collect();
    let c1 = data[..70].to_vec();
    let c2 = data[70..140].to_vec();
    let c3 = data[140..].to_vec();
    let mut m1 = member("s.bin", 0, data.clone(), c1);
    m1.flags = 0x14;
    let mut m2 = member("s.bin", 0, data.clone(), c2);
    m2.flags = 0x14;
    let m3 = member("s.bin", 0, data.clone(), c3);
    let e = arj_decode::decode_parts(&[&build_arj(&[m1]), &build_arj(&[m2]), &build_arj(&[m3])])
        .unwrap();
    assert_eq!(e[0].data, data);
}

#[test]
fn test_arj_oracle_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mix = mix_tokens();
    let stored_m = member(
        "stored.txt",
        0,
        b"stored member\n".to_vec(),
        b"stored member\n".to_vec(),
    );
    let members = [
        stored_m,
        member("m1.bin", 1, simulate(&mix), encode_lzh15(&mix)),
        member("m4.bin", 4, simulate(&mix), encode_fastest(&mix)),
    ];
    let expected: Vec<(&str, Vec<u8>)> = members
        .iter()
        .map(|m| (m.name, m.decoded.clone()))
        .collect();
    let arj = build_arj(&members);

    let oracles: &[&str] = &["unar", "7z"];
    let tools: Vec<&str> = oracles
        .iter()
        .copied()
        .filter(|t| {
            Command::new(t)
                .arg("--version")
                .output()
                .map(|o| o.status.success() || !o.stdout.is_empty())
                .unwrap_or(false)
        })
        .collect();
    if tools.is_empty() {
        return;
    }
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_arj_oracle_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.arj");
    std::fs::write(&path, &arj).unwrap();
    for t in &tools {
        let outdir = dir.join(format!("out_{t}"));
        let output = if *t == "unar" {
            Command::new(t)
                .args(["-D", "-o", outdir.to_str().unwrap()])
                .arg(&path)
                .output()
                .unwrap()
        } else {
            Command::new(t)
                .args(["x", "-y"])
                .arg(format!("-o{}", outdir.display()))
                .arg(&path)
                .output()
                .unwrap()
        };
        assert!(
            output.status.success(),
            "{t} extract failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for (name, want) in &expected {
            let got =
                std::fs::read(outdir.join(name)).unwrap_or_else(|_| panic!("{t}: missing {name}"));
            assert_eq!(&got, want, "{t}: {name} content mismatch");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================
// Encoder-side method 4 and multi-volume (finish_parts) tests.
// ============================================================

#[test]
fn test_arj_method4_encode_roundtrip() {
    use archive::archive::arj::encode::ArjEncoder;
    // Compressible payload: repeated phrase plus a counter tail.
    let mut data = Vec::new();
    for i in 0..400u32 {
        data.extend_from_slice(b"arj fastest method ");
        data.extend_from_slice(&i.to_le_bytes());
    }
    let mut enc = ArjEncoder::with_method(4).unwrap();
    enc.add_file("m4.bin", &data, 0).unwrap();
    let compressed = enc.finish();

    let entries = arj_decode::decode(&compressed).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "m4.bin");
    assert_eq!(entries[0].method, 4);
    assert_eq!(entries[0].data, data);

    // The compressed archive must beat stored for this input.
    let mut stored = ArjEncoder::new();
    stored.add_file("m4.bin", &data, 0).unwrap();
    assert!(compressed.len() < stored.finish().len());
}

#[test]
fn test_arj_method4_incompressible_stored() {
    use archive::archive::arj::encode::ArjEncoder;
    // High-entropy bytes (xorshift64*): a literal-only stream costs
    // 9/8 the input, so the encoder must fall back to method 0.
    let mut s = 0x1234_5678_9ABC_DEF0u64;
    let data: Vec<u8> = (0..2048)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 32) as u8
        })
        .collect();
    let mut enc = ArjEncoder::with_method(4).unwrap();
    enc.add_file("rand.bin", &data, 0).unwrap();
    let entries = arj_decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries[0].method, 0);
    assert_eq!(entries[0].data, data);
}

#[test]
fn test_arj_finish_parts_roundtrip() {
    use archive::archive::arj::encode::ArjEncoder;
    let data: Vec<u8> = (0u8..=255).cycle().take(2000).collect();
    let mut enc = ArjEncoder::new();
    enc.add_file("big.bin", &data, 0).unwrap();
    let parts = enc.finish_parts(512).unwrap();
    assert!(parts.len() >= 3);
    assert!(parts.iter().all(|p| p.len() <= 512));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let entries = arj_decode::decode_parts(&refs).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "big.bin");
    assert_eq!(entries[0].data, data);
    // A truncated part list is rejected as an unfinished split.
    assert!(arj_decode::decode_parts(&refs[..refs.len() - 1]).is_err());
    // The first volume alone ends mid-file.
    assert!(arj_decode::decode(&parts[0]).is_err());
}

#[test]
fn test_arj_finish_parts_mixed_entries() {
    use archive::archive::arj::encode::ArjEncoder;
    let a: Vec<u8> = (0u32..700).map(|i| (i * 31 % 256) as u8).collect();
    let b = b"second file stays whole".repeat(10);
    let mut enc = ArjEncoder::new();
    enc.add_dir("dir", 0).unwrap();
    enc.add_file("dir/a.bin", &a, 0).unwrap();
    enc.add_file("b.bin", &b, 0).unwrap();
    let parts = enc.finish_parts(600).unwrap();
    assert!(parts.len() >= 2);
    assert!(parts.iter().all(|p| p.len() <= 600));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let entries = arj_decode::decode_parts(&refs).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[0].is_dir);
    assert_eq!(entries[1].name, "dir/a.bin");
    assert_eq!(entries[1].data, a);
    assert_eq!(entries[2].data, b);
}

#[test]
fn test_arj_finish_parts_method4() {
    use archive::archive::arj::encode::ArjEncoder;
    let data = b"method four across volumes ".repeat(400);
    let mut enc = ArjEncoder::with_method(4).unwrap();
    enc.add_file("m4.bin", &data, 0).unwrap();
    let parts = enc.finish_parts(128).unwrap();
    assert!(parts.len() >= 2);
    assert!(parts.iter().all(|p| p.len() <= 128));
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let entries = arj_decode::decode_parts(&refs).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].method, 4);
    assert_eq!(entries[0].data, data);
}

#[test]
fn test_arj_finish_parts_single_volume() {
    use archive::archive::arj::encode::ArjEncoder;
    let mut enc = ArjEncoder::new();
    enc.add_file("one.bin", b"fits entirely", 0).unwrap();
    let parts = enc.finish_parts(1 << 20).unwrap();
    assert_eq!(parts.len(), 1);
    // A lone volume is a plain single-volume archive.
    let entries = arj_decode::decode(&parts[0]).unwrap();
    assert_eq!(entries[0].data, b"fits entirely");
}

#[test]
fn test_arj_finish_parts_rejects_tiny_volume() {
    use archive::archive::arj::encode::ArjEncoder;
    let mut enc = ArjEncoder::new();
    enc.add_file("x.bin", b"data", 0).unwrap();
    // No room for a member header plus payload in 64-byte volumes.
    assert!(enc.finish_parts(64).is_err());
}

// ============================================================
// Encoder-side methods 1-3 (LZH st1 static Huffman, 15-bit window).
// ============================================================

#[test]
fn test_arj_st1_encode_roundtrip() {
    use archive::archive::arj::encode::ArjEncoder;
    // Compressible payload with repeated phrases plus a counter.
    let mut data = Vec::new();
    for i in 0..400u32 {
        data.extend_from_slice(b"arj static huffman method ");
        data.extend_from_slice(&i.to_le_bytes());
    }
    // Methods 1-3 share one st1 wire format; each must roundtrip.
    for method in [1u8, 2, 3] {
        let mut enc = ArjEncoder::with_method(method).unwrap();
        enc.add_file("m.bin", &data, 0).unwrap();
        let compressed = enc.finish();
        let entries = arj_decode::decode(&compressed).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "m.bin");
        assert_eq!(entries[0].method, method);
        assert_eq!(entries[0].data, data);
        // The compressed archive must beat stored for this input.
        let mut stored = ArjEncoder::new();
        stored.add_file("m.bin", &data, 0).unwrap();
        assert!(compressed.len() < stored.finish().len());
    }
}

#[test]
fn test_arj_st1_incompressible_stored() {
    use archive::archive::arj::encode::ArjEncoder;
    // High-entropy bytes (xorshift32): the st1 stream plus table
    // overhead cannot win, so the encoder must fall back to stored.
    let mut s = 0x243F_6A88u32;
    let data: Vec<u8> = (0..2048)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 24) as u8
        })
        .collect();
    let mut enc = ArjEncoder::with_method(1).unwrap();
    enc.add_file("rand.bin", &data, 0).unwrap();
    let entries = arj_decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries[0].method, 0);
    assert_eq!(entries[0].data, data);
}

#[test]
fn test_arj_encoder_rejects_unsupported_method() {
    use archive::archive::arj::encode::ArjEncoder;
    for m in [0u8, 1, 2, 3, 4] {
        assert!(ArjEncoder::with_method(m).is_ok());
    }
    for m in [5u8, 9, u8::MAX] {
        assert!(ArjEncoder::with_method(m).is_err());
    }
}
