//! Unified error type for all decoding operations.

use core::fmt;

/// Unified error type for the archive crate.
///
/// All decoding functions return `Result<T, Error>`. With the `std` feature,
/// `Error` implements [`std::error::Error`] and converts into [`std::io::Error`].
///
/// # Examples
///
/// ```
/// use archive::error::Error;
///
/// let err = Error::InvalidData("bad header");
/// assert_eq!(err.to_string(), "invalid data: bad header");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Unexpected end of input data.
    UnexpectedEof,
    /// Invalid or corrupt data encountered.
    InvalidData(&'static str),
    /// Checksum verification failed.
    ChecksumMismatch { expected: u32, actual: u32 },
    /// 64-bit checksum verification failed.
    ChecksumMismatch64 { expected: u64, actual: u64 },
    /// Size verification failed.
    SizeMismatch { expected: u32, actual: u32 },
    /// Unsupported feature or format variant.
    Unsupported(&'static str),
    /// Decompressed output exceeds the specified size limit.
    OutputLimitExceeded {
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEof => write!(f, "unexpected end of input"),
            Error::InvalidData(msg) => write!(f, "invalid data: {msg}"),
            Error::ChecksumMismatch { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#010x}, got {actual:#010x}"
                )
            }
            Error::ChecksumMismatch64 { expected, actual } => {
                write!(
                    f,
                    "checksum mismatch: expected {expected:#018x}, got {actual:#018x}"
                )
            }
            Error::SizeMismatch { expected, actual } => {
                write!(f, "size mismatch: expected {expected}, got {actual}")
            }
            Error::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            Error::OutputLimitExceeded { limit } => {
                write!(f, "output limit exceeded: limit was {limit} bytes")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        match e {
            Error::UnexpectedEof => {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, e.to_string())
            }
            _ => std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn test_display_unexpected_eof() {
        let err = Error::UnexpectedEof;
        assert_eq!(format!("{err}"), "unexpected end of input");
    }

    #[test]
    fn test_display_invalid_data() {
        let err = Error::InvalidData("bad header");
        assert_eq!(format!("{err}"), "invalid data: bad header");
    }

    #[test]
    fn test_display_checksum_mismatch() {
        let err = Error::ChecksumMismatch {
            expected: 0xDEADBEEF,
            actual: 0x12345678,
        };
        assert_eq!(
            format!("{err}"),
            "checksum mismatch: expected 0xdeadbeef, got 0x12345678"
        );
    }

    #[test]
    fn test_display_size_mismatch() {
        let err = Error::SizeMismatch {
            expected: 100,
            actual: 200,
        };
        assert_eq!(format!("{err}"), "size mismatch: expected 100, got 200");
    }

    #[test]
    fn test_display_checksum_mismatch64() {
        let err = Error::ChecksumMismatch64 {
            expected: 0x0123_4567_89AB_CDEF,
            actual: 0xFEDC_BA98_7654_3210,
        };
        assert_eq!(
            format!("{err}"),
            "checksum mismatch: expected 0x0123456789abcdef, got 0xfedcba9876543210"
        );
    }

    #[test]
    fn test_display_unsupported() {
        let err = Error::Unsupported("bzip2 compression");
        assert_eq!(format!("{err}"), "unsupported: bzip2 compression");
    }

    #[test]
    fn test_display_output_limit_exceeded() {
        let err = Error::OutputLimitExceeded { limit: 1024 };
        assert_eq!(
            format!("{err}"),
            "output limit exceeded: limit was 1024 bytes"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_io_error_unexpected_eof() {
        let err = Error::UnexpectedEof;
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_io_error_invalid_data() {
        let err = Error::InvalidData("corrupt");
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_std_error_impl() {
        let err = Error::InvalidData("test");
        let std_err: &dyn std::error::Error = &err;
        // Verify it implements std::error::Error by calling its methods
        assert!(std_err.source().is_none());
    }

    #[test]
    fn test_checksum_mismatch_display_max() {
        let err = Error::ChecksumMismatch {
            expected: u32::MAX,
            actual: 0,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("0xffffffff"),
            "Display should contain u32::MAX in hex"
        );
        assert!(
            msg.contains("0x00000000"),
            "Display should contain 0 in hex"
        );
    }
}
