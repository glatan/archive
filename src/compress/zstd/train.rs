//! zstd dictionary training.
//!
//! This module builds a content-only `ZstdDict` from a set of
//! training samples. The current trainer focuses on selecting repeated byte
//! substrings to seed dictionary history for the crate's own
//! `encode_with_dict` / `decode_with_dict` APIs.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::xxhash;

use super::decode::ZstdDict;

/// Options for dictionary training.
#[derive(Debug, Clone, Copy)]
pub struct TrainOptions {
    /// Maximum number of content bytes to retain in the trained dictionary.
    pub max_dict_size: usize,
    /// Minimum repeated substring length considered during candidate extraction.
    pub min_match_len: usize,
    /// Optional explicit dictionary ID. If omitted, a deterministic non-zero ID
    /// is derived from the trained content.
    pub dict_id: Option<u32>,
}

impl Default for TrainOptions {
    fn default() -> Self {
        Self {
            max_dict_size: 4096,
            min_match_len: 8,
            dict_id: None,
        }
    }
}

/// Train a zstd dictionary from multiple samples.
///
/// The returned dictionary can be passed directly to
/// [`super::encode::encode_with_dict`] and [`super::decode::decode_with_dict`].
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if no non-empty samples are provided or the
/// training options are invalid.
pub fn train_dictionary(samples: &[&[u8]], options: &TrainOptions) -> Result<ZstdDict, Error> {
    if options.max_dict_size == 0 {
        return Err(Error::InvalidData("dictionary size must be non-zero"));
    }
    if options.min_match_len == 0 {
        return Err(Error::InvalidData("minimum match length must be non-zero"));
    }

    let non_empty: Vec<&[u8]> = samples
        .iter()
        .copied()
        .filter(|sample| !sample.is_empty())
        .collect();
    if non_empty.is_empty() {
        return Err(Error::InvalidData(
            "dictionary training requires non-empty samples",
        ));
    }

    let content =
        build_dictionary_content(&non_empty, options.max_dict_size, options.min_match_len);
    let dict_id = options
        .dict_id
        .unwrap_or_else(|| derive_dictionary_id(&content));

    ZstdDict::from_content(dict_id, &content)
}

fn build_dictionary_content(
    samples: &[&[u8]],
    max_dict_size: usize,
    min_match_len: usize,
) -> Vec<u8> {
    let mut candidate_counts: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    let mut window_lengths = Vec::new();
    window_lengths.push(min_match_len);
    window_lengths.push((min_match_len * 2).min(32));
    window_lengths.push((min_match_len * 4).min(64));
    window_lengths.sort_unstable();
    window_lengths.dedup();

    for &sample in samples {
        for &window_len in &window_lengths {
            if sample.len() < window_len {
                continue;
            }
            let step = (window_len / 2).max(1);
            let mut pos = 0usize;
            while pos + window_len <= sample.len() {
                let window = sample[pos..pos + window_len].to_vec();
                *candidate_counts.entry(window).or_insert(0) += 1;
                pos += step;
            }
        }
    }

    let mut candidates: Vec<(usize, Vec<u8>)> = candidate_counts
        .into_iter()
        .filter(|(window, count)| *count > 1 && window.len() >= min_match_len)
        .map(|(window, count)| (count * window.len(), window))
        .collect();
    candidates.sort_unstable_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.len().cmp(&a.1.len()))
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut content = Vec::new();
    for (_, candidate) in candidates {
        if contains_subslice(&content, &candidate) {
            continue;
        }
        if content.len() + candidate.len() > max_dict_size {
            continue;
        }
        content.extend_from_slice(&candidate);
        if content.len() >= max_dict_size {
            break;
        }
    }

    if content.is_empty() {
        backfill_from_samples(&mut content, samples, max_dict_size, min_match_len);
    } else if content.len() < max_dict_size {
        let remaining_budget = max_dict_size - content.len();
        backfill_from_samples(&mut content, samples, remaining_budget, min_match_len);
    }

    if content.len() > max_dict_size {
        content.truncate(max_dict_size);
    }
    content
}

fn backfill_from_samples(
    content: &mut Vec<u8>,
    samples: &[&[u8]],
    remaining_budget: usize,
    min_match_len: usize,
) {
    if remaining_budget == 0 {
        return;
    }

    let mut remaining = remaining_budget;
    let mut ordered: Vec<&[u8]> = samples.to_vec();
    ordered.sort_unstable_by_key(|sample| core::cmp::Reverse(sample.len()));

    for sample in ordered {
        if remaining == 0 {
            break;
        }

        let take = sample
            .len()
            .min(remaining)
            .max(min_match_len.min(sample.len()));
        let slice = &sample[..take];
        if contains_subslice(content, slice) {
            continue;
        }
        content.extend_from_slice(slice);
        remaining = remaining.saturating_sub(slice.len());
    }
}

fn derive_dictionary_id(content: &[u8]) -> u32 {
    let hash = xxhash::xxhash64(content, 0);
    let id = (hash as u32) ^ ((hash >> 32) as u32);
    if id == 0 { 1 } else { id }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::zstd::{decode, encode};

    #[test]
    fn test_train_dictionary_rejects_empty_samples() {
        let result = train_dictionary(&[], &TrainOptions::default());
        assert!(matches!(
            result,
            Err(Error::InvalidData(
                "dictionary training requires non-empty samples"
            ))
        ));
    }

    #[test]
    fn test_train_dictionary_preserves_explicit_id() {
        let options = TrainOptions {
            dict_id: Some(0x1234_5678),
            ..TrainOptions::default()
        };
        let dict = train_dictionary(&[b"repeat repeat repeat".as_slice()], &options).unwrap();
        assert_eq!(dict.id, 0x1234_5678);
    }

    #[test]
    fn test_train_dictionary_captures_common_phrase() {
        let samples = [
            b"archive crate common prefix and shared phrase".as_slice(),
            b"another archive crate common prefix for testing".as_slice(),
            b"archive crate common prefix appears again".as_slice(),
        ];
        let dict = train_dictionary(&samples, &TrainOptions::default()).unwrap();
        assert!(
            dict.content
                .windows(b"archive ".len())
                .any(|w| w == b"archive "),
            "trained content should retain repeated sample material"
        );
    }

    #[test]
    fn test_train_dictionary_roundtrip_with_encode_decode() {
        let samples = [
            b"the quick brown fox jumps over the lazy dog".as_slice(),
            b"the quick brown fox writes regression tests".as_slice(),
            b"the quick brown fox fixes interoperability bugs".as_slice(),
        ];
        let dict = train_dictionary(&samples, &TrainOptions::default()).unwrap();
        let input = b"the quick brown fox jumps over the lazy dog twice";
        let encoded = encode::encode_with_dict(input, &dict);
        let decoded = decode::decode_with_dict(&encoded, &dict).unwrap();
        assert_eq!(decoded, input);
    }
}
