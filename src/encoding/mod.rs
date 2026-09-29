//! Byte-oriented encoding format implementations.
//!
//! These modules implement textual byte encodings that wrap raw data (and a
//! small amount of file metadata, where the format defines it) into a
//! transferable text stream. They are not compression: output is larger than
//! input. Format-specific scope details live in each module doc comment and
//! in `docs/spec/`.

/// uuencode (POSIX.1-2017 historical and Base64 algorithms).
#[cfg(feature = "uuencode")]
pub mod uuencode;

/// yEnc binary-to-text encoding (draft 1.3).
#[cfg(feature = "yenc")]
pub mod yenc;

/// MacBinary II container format.
#[cfg(feature = "macbinary")]
pub mod macbinary;

/// BinHex 4.0 (.hqx) encoding.
#[cfg(feature = "binhex")]
pub mod binhex;

/// Ascii85 (Adobe  and RFC 1924 Base-85).
#[cfg(feature = "ascii85")]
pub mod ascii85;
