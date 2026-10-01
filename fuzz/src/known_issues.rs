//! Known external-tool incompatibilities for fuzz cross-validation.
//!
//! These are not library correctness bugs. They represent intentional
//! interoperability gaps or external-tool quirks that should not be saved as
//! actionable failures.

use crate::algorithms::Algorithm;
use crate::report::TestPattern;

/// Return a human-readable reason when `error` matches a known non-actionable
/// incompatibility for the given `(algo, pattern, data)` tuple.
pub fn classify(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
    error: &str,
) -> Option<&'static str> {
    if is_lrzip_outer_container_gap(algo, pattern) {
        return Some("system lrzip outer .lrz framing is not fully compatible");
    }

    if is_lrzip_external_output_gap(algo, pattern, error) {
        return Some(
            "system lrzip output uses container/backend combinations we do not fully decode",
        );
    }

    if is_lzw_empty_input_quirk(algo, pattern, data, error) {
        return Some("ncompress rejects empty input for external compress/decompress");
    }

    if is_lzw_bits9_roundtrip_loss(algo, pattern, error) {
        return Some("ncompress -b 9 produces lossy output for certain data patterns");
    }

    if is_sevenz_empty_stream_entry(algo, pattern, data, error) {
        return Some(
            "system 7z stores empty files as empty-stream entries which are not supported",
        );
    }

    None
}

fn is_lrzip_outer_container_gap(algo: Algorithm, pattern: TestPattern) -> bool {
    matches!(
        algo,
        Algorithm::LrzipLzma
            | Algorithm::LrzipBzip2
            | Algorithm::LrzipGzip
            | Algorithm::LrzipLzo
            | Algorithm::LrzipNone
            | Algorithm::LrzipZpaq
    ) && pattern == TestPattern::OriginalDecompress
}

fn is_lrzip_external_output_gap(algo: Algorithm, pattern: TestPattern, error: &str) -> bool {
    matches!(
        algo,
        Algorithm::LrzipLzma
            | Algorithm::LrzipBzip2
            | Algorithm::LrzipGzip
            | Algorithm::LrzipLzo
            | Algorithm::LrzipNone
            | Algorithm::LrzipZpaq
    ) && pattern == TestPattern::OriginalCompress
        && (error.contains("unsupported: lrzip: unsupported compression type")
            || error.contains("unexpected end of input")
            || error.contains("invalid data: rzip: match offset out of range")
            || (algo == Algorithm::LrzipZpaq && error.contains("zpaq: unsupported hcomp opcode")))
}

fn is_lzw_empty_input_quirk(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
    error: &str,
) -> bool {
    (algo == Algorithm::Lzw || algo == Algorithm::LzwBits9)
        && matches!(
            pattern,
            TestPattern::OriginalCompress | TestPattern::OriginalDecompress
        )
        && data.is_empty()
        && (error.contains("compress exited with")
            || error.contains("uncompress exited with")
            || error.contains("empty input"))
}

/// System `7z` stores empty files as empty-stream entries rather than using a
/// regular data stream.  Our decoder does not implement the empty-stream /
/// empty-files header fields (intentional scope exclusion per `docs/spec/sevenz/`).
fn is_sevenz_empty_stream_entry(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
    error: &str,
) -> bool {
    matches!(
        algo,
        Algorithm::SevenZ
            | Algorithm::SevenZCopy
            | Algorithm::SevenZLzma
            | Algorithm::SevenZPpmd
            | Algorithm::SevenZDeflate
            | Algorithm::SevenZBzip2
    ) && pattern == TestPattern::OriginalCompress
        && data.is_empty()
        && error.contains("empty-stream entries are not supported")
}

/// ncompress `compress -b 9` has a known bug where the roundtrip is lossy
/// for certain data patterns (the system `uncompress` itself also fails to
/// recover the original data).  This is an external tool issue, not ours.
fn is_lzw_bits9_roundtrip_loss(algo: Algorithm, pattern: TestPattern, error: &str) -> bool {
    algo == Algorithm::LzwBits9
        && pattern == TestPattern::OriginalCompress
        && error.contains("mismatch")
}

#[cfg(test)]
mod tests {
    use super::classify;
    use crate::algorithms::Algorithm;
    use crate::report::TestPattern;

    #[test]
    fn classifies_lrzip_original_decompress_as_known_issue() {
        let issue = classify(
            Algorithm::LrzipLzma,
            TestPattern::OriginalDecompress,
            b"hello",
            "lrzip exited with exit status: 1: Fatal error - exiting",
        );
        assert!(issue.is_some());
    }

    #[test]
    fn classifies_lrzip_original_compress_unsupported_type_as_known_issue() {
        let issue = classify(
            Algorithm::LrzipNone,
            TestPattern::OriginalCompress,
            b"hello",
            "unsupported: lrzip: unsupported compression type",
        );
        assert!(issue.is_some());
    }

    #[test]
    fn classifies_lrzip_original_compress_unexpected_eof_as_known_issue() {
        let issue = classify(
            Algorithm::LrzipLzma,
            TestPattern::OriginalCompress,
            b"hello",
            "unexpected end of input",
        );
        assert!(issue.is_some());
    }

    #[test]
    fn classifies_lrzip_original_compress_match_offset_as_known_issue() {
        let issue = classify(
            Algorithm::LrzipGzip,
            TestPattern::OriginalCompress,
            b"hello",
            "invalid data: rzip: match offset out of range",
        );
        assert!(issue.is_some());
    }

    #[test]
    fn classifies_lrzip_original_compress_zpaq_hcomp_as_known_issue() {
        let issue = classify(
            Algorithm::LrzipZpaq,
            TestPattern::OriginalCompress,
            b"hello",
            "invalid data: zpaq: unsupported hcomp opcode",
        );
        assert!(issue.is_some());
    }

    #[test]
    fn classifies_lzw_empty_input_external_quirk_as_known_issue() {
        let issue = classify(
            Algorithm::Lzw,
            TestPattern::OriginalCompress,
            b"",
            "compress exited with exit status: 2:",
        );
        assert!(issue.is_some());
    }

    #[test]
    fn classifies_sevenz_empty_input_as_known_issue() {
        for algo in [
            Algorithm::SevenZ,
            Algorithm::SevenZCopy,
            Algorithm::SevenZLzma,
            Algorithm::SevenZPpmd,
            Algorithm::SevenZDeflate,
            Algorithm::SevenZBzip2,
        ] {
            let issue = classify(
                algo,
                TestPattern::OriginalCompress,
                b"",
                "unsupported: 7z: empty-stream entries are not supported",
            );
            assert!(
                issue.is_some(),
                "{algo:?} empty input should be known issue"
            );
        }
    }

    #[test]
    fn does_not_hide_sevenz_failures_with_nonempty_input() {
        let issue = classify(
            Algorithm::SevenZ,
            TestPattern::OriginalCompress,
            b"hello",
            "unsupported: 7z: empty-stream entries are not supported",
        );
        assert!(issue.is_none(), "non-empty 7z should not be filtered");
    }

    #[test]
    fn does_not_hide_real_xz_failures() {
        let issue = classify(
            Algorithm::Xz,
            TestPattern::OriginalCompress,
            b"hello",
            "unexpected end of input",
        );
        assert!(issue.is_none());
    }
}
