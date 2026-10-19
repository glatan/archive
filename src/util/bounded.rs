//! Output size limit helpers for decompression bomb protection.

use crate::error::Error;

/// Largest declared output size that may be allocated or used as a decode
/// loop bound. Larger header fields are rejected before conversion to `usize`.
#[cfg_attr(
    not(any(
        feature = "sevenz",
        feature = "zip",
        feature = "git-pack",
        feature = "lzip",
        feature = "xz",
        feature = "lrzip",
        feature = "lzma-alone",
    )),
    allow(dead_code)
)]
pub(crate) const DECLARED_OUTPUT_LIMIT: usize = 1 << 30;

/// Accept a header-declared output length only when it fits in `usize` and
/// does not exceed [`DECLARED_OUTPUT_LIMIT`].
#[cfg_attr(not(any(feature = "zip", feature = "git-pack")), allow(dead_code))]
pub(crate) fn declared_output_len(size: u64) -> Result<usize, Error> {
    let size = usize::try_from(size).map_err(|_| Error::OutputLimitExceeded {
        limit: DECLARED_OUTPUT_LIMIT,
    })?;
    if size > DECLARED_OUTPUT_LIMIT {
        return Err(Error::OutputLimitExceeded {
            limit: DECLARED_OUTPUT_LIMIT,
        });
    }
    Ok(size)
}

/// Check whether appending `additional` bytes to a buffer of `current` bytes
/// would exceed `limit`. Returns `Ok(())` if within limit or if limit is
/// `None`, or `Err(Error::OutputLimitExceeded)` otherwise.
#[inline]
#[allow(dead_code)]
pub(crate) const fn check_output_limit(
    current: usize,
    additional: usize,
    limit: Option<usize>,
) -> Result<(), Error> {
    if let Some(max) = limit
        && current.saturating_add(additional) > max
    {
        return Err(Error::OutputLimitExceeded { limit: max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limit() {
        assert!(check_output_limit(100, 50, Some(200)).is_ok());
    }

    #[test]
    fn at_exact_limit() {
        assert!(check_output_limit(100, 100, Some(200)).is_ok());
    }

    #[test]
    fn exceeds_limit() {
        let err = check_output_limit(100, 101, Some(200)).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { limit: 200 }));
    }

    #[test]
    fn no_limit() {
        assert!(check_output_limit(usize::MAX, 1, None).is_ok());
    }

    #[test]
    fn zero_limit() {
        let err = check_output_limit(0, 1, Some(0)).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { limit: 0 }));
    }

    #[test]
    fn zero_additional_at_limit() {
        assert!(check_output_limit(200, 0, Some(200)).is_ok());
    }

    #[test]
    fn saturating_overflow() {
        let err = check_output_limit(usize::MAX, 1, Some(100)).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { limit: 100 }));
    }

    #[test]
    fn zero_at_zero_limit() {
        assert!(check_output_limit(0, 0, Some(0)).is_ok());
    }

    #[test]
    fn declared_output_len_accepts_one_gib() {
        assert_eq!(declared_output_len(1 << 30).unwrap(), 1 << 30);
    }

    #[test]
    fn declared_output_len_rejects_above_one_gib() {
        let err = declared_output_len((1 << 30) + 1).unwrap_err();
        assert!(matches!(
            err,
            Error::OutputLimitExceeded {
                limit: DECLARED_OUTPUT_LIMIT
            }
        ));
    }

    #[test]
    fn declared_output_len_rejects_value_that_does_not_fit_usize() {
        let err = declared_output_len(u64::MAX).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
    }
}
