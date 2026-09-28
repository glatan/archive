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

/// RPM package (`.rpm`) read support.
#[cfg(feature = "rpm")]
pub mod rpm;

/// SquashFS (`.squashfs`) image read support.
#[cfg(feature = "squashfs")]
pub mod squashfs;

#[cfg(feature = "cramfs")]
pub mod cramfs;

#[cfg(feature = "crx3")]
pub mod crx3;
#[cfg(feature = "pea")]
pub mod pea;
#[cfg(feature = "romfs")]
pub mod romfs;

/// Linux erofs read-only filesystem image read support.
#[cfg(feature = "erofs")]
pub mod erofs;

/// ISO 9660 filesystem image read support (Rock Ridge / Joliet).
#[cfg(feature = "iso9660")]
pub mod iso9660;

/// Microsoft Cabinet (`.cab`) archive read support.
#[cfg(feature = "mscab")]
pub mod mscab;

#[cfg(feature = "mscfb")]
pub mod mscfb;

/// ZIM (`.zim`) archive read support.
#[cfg(feature = "zim")]
pub mod zim;

/// mtree(5) manifest read support.
#[cfg(feature = "mtree")]
pub mod mtree;

/// WARC (Web ARChive, `.warc`) record read support.
#[cfg(feature = "warc")]
pub mod warc;

/// LHA/LZH archive support (store methods only).
#[cfg(feature = "lha")]
pub mod lha;

/// ARJ archive support (store method only).
#[cfg(feature = "arj")]
pub mod arj;

/// SEA ARC archive support (store methods only).
#[cfg(feature = "arc")]
pub mod arc;

/// Git pack format (`pack-*.pack` / `pack-*.idx`) support.
#[cfg(feature = "git-pack")]
pub mod git_pack;

/// XAR (eXtensible ARchive) format support.
#[cfg(feature = "xar")]
pub mod xar;
