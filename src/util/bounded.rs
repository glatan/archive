//! Output size limit helpers for decompression bomb protection.

use crate::error::Error;

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
}
