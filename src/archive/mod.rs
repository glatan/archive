//! Archive format implementations.
//!
//! These modules provide in-memory archive/container read/write APIs.
//! Format-specific scope details live in each submodule doc comment and in
//! `docs/spec/`.

/// tar archive format (UStar with GNU and PAX extensions).
#[cfg(feature = "tar")]
pub mod tar;

/// cpio archive format (`odc`, SVR4 `newc`, and `newcrc`).
#[cfg(feature = "cpio")]
pub mod cpio;

/// ar archive format (GNU/BSD dialects).
#[cfg(feature = "ar")]
pub mod ar;

/// zpaq multi-entry archive format.
#[cfg(feature = "zpaq")]
pub mod zpaq;

/// ZIP archive support.
#[cfg(feature = "zip")]
pub mod zip;

/// 7z archive support.
#[cfg(feature = "sevenz")]
pub mod sevenz;

/// Debian binary package (`.deb`) read support.
#[cfg(feature = "deb")]
pub mod deb;
