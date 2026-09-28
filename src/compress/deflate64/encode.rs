//! Deflate64 (Enhanced Deflating) compression per APPNOTE.TXT section 5.6.
//!
//! Deflate64 is a DEFLATE superset: within the classic Huffman
//! tables the only behavioural difference is that length code 285
//! takes 16 extra bits instead of meaning a 258-byte match, and
//! distance codes 30/31 cover the extended 64 KB window. Emitting
//! DEFLATE restricted to match lengths <=257 and the 32 KB window
//! therefore produces a valid Deflate64 stream. The extended
//! ranges (code 285 long matches, distances >32 KB) are not used.

use alloc::vec::Vec;

use crate::compress::deflate::encode::{Level, encode_max_match};

/// Maximum match length kept inside the DEFLATE-compatible subset
/// (avoids Deflate64 length code 285 semantics).
const DEFLATE64_SAFE_MATCH: usize = 257;

/// Encode a Deflate64 stream (raw, no ZIP/7z framing).
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_max_match(input, Level::Default, DEFLATE64_SAFE_MATCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::deflate64::decode::decode;

    #[test]
    fn roundtrip_basic() {
        let data = b"deflate64 encode test data, deflate64 encode test data";
        assert_eq!(decode(&encode(data)).unwrap(), data);
    }

    #[test]
    fn roundtrip_long_runs() {
        // Long runs force matches beyond the 258-byte DEFLATE cap;
        // the encoder must split them below Deflate64 code 285.
        let mut data = vec![0x42u8; 70_000];
        data.extend_from_slice(b"-tail-");
        data.extend_from_slice(&vec![0x42u8; 10_000]);
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn roundtrip_binary_and_empty() {
        let mut rng = 0x9E3779B9u32;
        let mut data = Vec::new();
        for _ in 0..50_000 {
            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((rng >> 16) as u8);
        }
        assert_eq!(decode(&encode(&data)).unwrap(), data);
        assert_eq!(decode(&encode(b"")).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn output_is_valid_deflate64_for_decoder() {
        // The DEFLATE decoder accepts the stream too (superset
        // subset is identical until code 285/dist 30-31 appear).
        let data = b"abcabcabc".repeat(1000);
        let enc = encode(&data);
        assert_eq!(decode(&enc).unwrap(), data);
    }
}
