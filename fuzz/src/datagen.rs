//! Random test-data generator.
//!
//! Generates byte vectors with varying sizes and content patterns designed to
//! exercise different code paths in compression/archive codecs:
//!
//! - **PureRandom** — high entropy, incompressible data.
//! - **Repetitive** — short pattern repeated, highly compressible.
//! - **Zeros** — all-zero bytes, degenerate case for many codecs.
//! - **Mixed** — half random, half repetitive.
//! - **Structured** — printable ASCII text with newlines.
//!
//! Sizes follow a log-uniform distribution across four buckets
//! (tiny / small / medium / large) so that both boundary-size inputs
//! and bulk inputs get adequate coverage.

use rand::Rng;
use rand::RngExt;

/// Content pattern used to generate test data.
#[derive(Debug, Clone, Copy)]
enum Pattern {
    PureRandom,
    Repetitive,
    Zeros,
    Mixed,
    Structured,
}

const PATTERNS: [Pattern; 5] = [
    Pattern::PureRandom,
    Pattern::Repetitive,
    Pattern::Zeros,
    Pattern::Mixed,
    Pattern::Structured,
];

pub struct StructuredCase {
    pub label: String,
    pub data: Vec<u8>,
}

/// Generate a random byte vector with a size in `min_size..=max_size` and a
/// randomly chosen content pattern.
pub fn generate(rng: &mut impl Rng, min_size: usize, max_size: usize) -> Vec<u8> {
    let size = generate_size(rng, min_size, max_size);
    let pattern = PATTERNS[rng.random_range(0..PATTERNS.len())];
    generate_with_pattern(rng, size, pattern)
}

pub fn mutate(rng: &mut impl Rng, base: &[u8], min_size: usize, max_size: usize) -> Vec<u8> {
    let mut data = if base.is_empty() {
        generate(rng, min_size, max_size)
    } else {
        base.to_vec()
    };

    let operations = rng.random_range(1..=4);
    for _ in 0..operations {
        match rng.random_range(0..5) {
            0 => {
                if !data.is_empty() {
                    let idx = rng.random_range(0..data.len());
                    data[idx] ^= 1 << rng.random_range(0..8);
                }
            }
            1 => {
                if data.len() < max_size {
                    let idx = rng.random_range(0..=data.len());
                    data.insert(idx, rng.random_range(0..=255) as u8);
                }
            }
            2 => {
                if !data.is_empty() && data.len() > min_size {
                    let idx = rng.random_range(0..data.len());
                    data.remove(idx);
                }
            }
            3 => {
                if !data.is_empty() {
                    let start = rng.random_range(0..data.len());
                    let end = rng.random_range(start..data.len());
                    let fill = rng.random_range(0..=255) as u8;
                    for byte in &mut data[start..=end] {
                        *byte = fill;
                    }
                }
            }
            _ => {
                if !data.is_empty() && data.len() < max_size {
                    let start = rng.random_range(0..data.len());
                    let end = (start + rng.random_range(1..=8)).min(data.len());
                    let repeated = data[start..end].to_vec();
                    let allowed = max_size.saturating_sub(data.len());
                    let insert_at = rng.random_range(0..=data.len());
                    data.splice(insert_at..insert_at, repeated.into_iter().take(allowed));
                }
            }
        }
    }

    if data.len() < min_size {
        data.resize(min_size, 0);
    }
    if data.len() > max_size {
        data.truncate(max_size);
    }
    data
}

pub fn structured_cases(min_size: usize, max_size: usize) -> Vec<StructuredCase> {
    let mut cases = Vec::new();

    add_case(&mut cases, min_size, max_size, "empty", Vec::new());
    add_case(&mut cases, min_size, max_size, "single-zero", vec![0]);
    add_case(&mut cases, min_size, max_size, "single-ff", vec![0xff]);
    add_case(&mut cases, min_size, max_size, "pair-ab", b"AB".to_vec());

    for &size in &[
        3usize, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 1023, 1024,
    ] {
        add_case(
            &mut cases,
            min_size,
            max_size,
            &format!("zeros-{size}"),
            vec![0; size],
        );
        add_case(
            &mut cases,
            min_size,
            max_size,
            &format!("incrementing-{size}"),
            (0..size).map(|i| (i % 256) as u8).collect(),
        );
        add_case(
            &mut cases,
            min_size,
            max_size,
            &format!("repeating-ab-{size}"),
            repeating_bytes(b"AB", size),
        );
    }

    add_case(
        &mut cases,
        min_size,
        max_size,
        "structured-text-256",
        repeating_bytes(b"line one\nline two\nline three\n", 256),
    );
    add_case(
        &mut cases,
        min_size,
        max_size,
        "high-entropy-257",
        (0..257).map(|i| ((i * 73 + 19) % 256) as u8).collect(),
    );

    cases
}

fn generate_size(rng: &mut impl Rng, min_size: usize, max_size: usize) -> usize {
    if min_size >= max_size {
        return min_size;
    }

    // Log-uniform distribution across 4 buckets
    let bucket: u8 = rng.random_range(0..4);
    let (lo, hi) = match bucket {
        0 => (min_size, 100.min(max_size)),
        1 => (100.min(max_size), (10 * 1024).min(max_size)),
        2 => ((10 * 1024).min(max_size), (100 * 1024).min(max_size)),
        _ => ((100 * 1024).min(max_size), max_size),
    };

    if lo >= hi {
        lo
    } else {
        rng.random_range(lo..=hi)
    }
}

fn generate_with_pattern(rng: &mut impl Rng, size: usize, pattern: Pattern) -> Vec<u8> {
    match pattern {
        Pattern::PureRandom => generate_pure_random(rng, size),
        Pattern::Repetitive => generate_repetitive(rng, size),
        Pattern::Zeros => vec![0u8; size],
        Pattern::Mixed => generate_mixed(rng, size),
        Pattern::Structured => generate_structured(rng, size),
    }
}

fn generate_pure_random(rng: &mut impl Rng, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

fn generate_repetitive(rng: &mut impl Rng, size: usize) -> Vec<u8> {
    if size == 0 {
        return Vec::new();
    }
    let pattern_len = rng.random_range(1..=32.min(size));
    let mut pattern = vec![0u8; pattern_len];
    rng.fill(&mut pattern[..]);

    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        let remaining = size - data.len();
        let chunk = remaining.min(pattern_len);
        data.extend_from_slice(&pattern[..chunk]);
    }
    data
}

fn generate_mixed(rng: &mut impl Rng, size: usize) -> Vec<u8> {
    if size == 0 {
        return Vec::new();
    }
    let half = size / 2;
    let mut data = generate_pure_random(rng, half);
    let rest = generate_repetitive(rng, size - half);
    data.extend_from_slice(&rest);
    data
}

fn generate_structured(rng: &mut impl Rng, size: usize) -> Vec<u8> {
    // ASCII text-like data: printable characters with occasional newlines
    let mut data = Vec::with_capacity(size);
    for _ in 0..size {
        let ch: u8 = if rng.random_range(0..10) == 0 {
            b'\n'
        } else {
            rng.random_range(0x20..=0x7e)
        };
        data.push(ch);
    }
    data
}

fn add_case(
    cases: &mut Vec<StructuredCase>,
    min_size: usize,
    max_size: usize,
    label: &str,
    data: Vec<u8>,
) {
    if data.len() < min_size || data.len() > max_size {
        return;
    }
    cases.push(StructuredCase {
        label: label.to_string(),
        data,
    });
}

fn repeating_bytes(pattern: &[u8], size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        let remaining = size - data.len();
        let chunk = remaining.min(pattern.len());
        data.extend_from_slice(&pattern[..chunk]);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::{mutate, structured_cases};

    #[test]
    fn structured_cases_include_boundary_inputs() {
        let cases = structured_cases(0, 1024);
        let labels: Vec<_> = cases.iter().map(|case| case.label.as_str()).collect();
        assert!(labels.contains(&"empty"));
        assert!(labels.contains(&"single-zero"));
        assert!(labels.contains(&"zeros-512"));
        assert!(labels.contains(&"incrementing-1024"));
    }

    #[test]
    fn structured_cases_respect_size_bounds() {
        let cases = structured_cases(10, 16);
        assert!(
            cases
                .iter()
                .all(|case| (10..=16).contains(&case.data.len()))
        );
    }

    #[test]
    fn mutate_respects_size_bounds() {
        let mut rng = rand::rng();
        let mutated = mutate(&mut rng, b"abcdef", 4, 8);
        assert!((4..=8).contains(&mutated.len()));
    }
}
