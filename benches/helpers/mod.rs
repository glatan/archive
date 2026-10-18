/// Generate deterministic compressible data of the given size.
///
/// Uses a simple LCG to produce byte values biased toward ASCII text,
/// giving compression algorithms a realistic mix of redundancy.
pub fn generate_text_data(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
    let words: &[&[u8]] = &[
        b"the ",
        b"quick ",
        b"brown ",
        b"fox ",
        b"jumps ",
        b"over ",
        b"lazy ",
        b"dog ",
        b"archive ",
        b"compress ",
        b"benchmark ",
        b"data ",
        b"test ",
        b"rust ",
        b"format ",
        b"encode ",
        b"decode ",
        b"stream ",
        b"block ",
        b"header ",
        b"checksum ",
        b"entry ",
    ];
    while buf.len() < size {
        // LCG step
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let idx = ((state >> 33) as usize) % words.len();
        let word = words[idx];
        let remaining = size - buf.len();
        if remaining >= word.len() {
            buf.extend_from_slice(word);
        } else {
            buf.extend_from_slice(&word[..remaining]);
        }
        // Occasionally add a newline
        if buf.len() < size && (state >> 40) & 0x07 == 0 {
            buf.push(b'\n');
        }
    }
    buf.truncate(size);
    buf
}

/// Generate a single repeated byte. Matches overlap on every copy.
///
/// `archive` benches keep a single text corpus, so this stays unused there.
#[allow(dead_code)]
pub fn generate_run_data(size: usize) -> Vec<u8> {
    vec![0xA5; size]
}

/// Generate a 4-byte periodic pattern.
///
/// `archive` benches keep a single text corpus, so this stays unused there.
#[allow(dead_code)]
pub fn generate_periodic_data(size: usize) -> Vec<u8> {
    const PATTERN: [u8; 4] = [0x10, 0x20, 0x30, 0x40];
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let n = (size - buf.len()).min(PATTERN.len());
        buf.extend_from_slice(&PATTERN[..n]);
    }
    buf
}

/// Generate deterministic binary data (less compressible) of the given size.
///
/// `archive` benches keep a single text corpus, so this stays unused there.
#[allow(dead_code)]
pub fn generate_binary_data(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut state: u64 = 0x0123_4567_89AB_CDEF;
    while buf.len() < size {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1442695040888963407);
        buf.extend_from_slice(&state.to_le_bytes());
    }
    buf.truncate(size);
    buf
}

/// One compression-bench input.
///
/// `archive` benches keep a single text corpus, so this stays unused there.
#[allow(dead_code)]
pub struct BenchInput {
    /// Criterion parameter. The repetitive text corpus keeps the historical
    /// size id (`4KiB`, `256KiB`, `1KiB`) so those series stay comparable.
    pub label: String,
    pub data: Vec<u8>,
    /// `true` for the 4MiB cases, which use a shorter Criterion sample.
    pub large: bool,
}

/// Text, single-byte run, incompressible bytes, and a 4-byte period.
///
/// `with_4mib` appends a 4MiB size. Those cases are marked [`BenchInput::large`]
/// and are emitted after the smaller sizes.
///
/// `archive` benches keep a single text corpus, so this stays unused there.
#[allow(dead_code)]
pub fn compression_inputs(sizes: &[(&str, usize)], with_4mib: bool) -> Vec<BenchInput> {
    let mut sizes: Vec<(&str, usize)> = sizes.to_vec();
    if with_4mib {
        sizes.push(("4MiB", 4 * 1024 * 1024));
    }
    let mut out = Vec::new();
    for &(size_label, size) in &sizes {
        let large = size >= 4 * 1024 * 1024;
        let corpora = [
            ("", generate_text_data as fn(usize) -> Vec<u8>),
            ("run", generate_run_data as fn(usize) -> Vec<u8>),
            ("random", generate_binary_data as fn(usize) -> Vec<u8>),
            ("periodic", generate_periodic_data as fn(usize) -> Vec<u8>),
        ];
        for (name, generate) in corpora {
            let label = if name.is_empty() {
                size_label.to_string()
            } else {
                format!("{name}/{size_label}")
            };
            out.push(BenchInput {
                label,
                data: generate(size),
                large,
            });
        }
    }
    out
}
