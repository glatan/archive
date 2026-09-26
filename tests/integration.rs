#![cfg(all(
    feature = "ar",
    feature = "deb",
    feature = "rpm",
    feature = "squashfs",
    feature = "mscab",
    feature = "zim",
    feature = "cpio",
    feature = "tar",
    feature = "bzip2",
    feature = "deflate",
    feature = "gzip",
    feature = "lrzip",
    feature = "lz4",
    feature = "lzip",
    feature = "lzma-alone",
    feature = "lzo",
    feature = "lzw",
    feature = "snappy",
    feature = "xz",
    feature = "zlib",
    feature = "zstd",
    feature = "zpaq"
))]

use archive::archive::ar;
use archive::archive::cpio;
use archive::archive::deb;
use archive::archive::rpm;
#[cfg(feature = "sevenz")]
use archive::archive::sevenz;
use archive::archive::squashfs;
use archive::archive::tar;
#[cfg(feature = "zip")]
use archive::archive::zip;
use archive::archive::zpaq;
#[cfg(feature = "brotli")]
use archive::compress::brotli;
use archive::compress::bzip2;
use archive::compress::deflate;
use archive::compress::gzip;
use archive::compress::lrzip;
use archive::compress::lz4;
use archive::compress::lzip;
use archive::compress::lzma_alone;
use archive::compress::lzo;
use archive::compress::lzw;
#[cfg(feature = "rzip")]
use archive::compress::rzip;
use archive::compress::snappy;
use archive::compress::xz;
use archive::compress::zlib;
use archive::compress::zstd;

// ============================================================
// 7z tests
// ============================================================

#[cfg(feature = "sevenz")]
fn sevenz_binary() -> Option<&'static str> {
    use std::process::Command;

    for candidate in ["7z", "7zz", "7zr"] {
        if let Ok(output) = Command::new(candidate).arg("i").output()
            && output.status.success()
        {
            return Some(candidate);
        }
    }
    None
}
// ============================================================
// lrzip tests
// ============================================================

fn lrzip_binary() -> Option<&'static str> {
    use std::process::Command;

    if let Ok(output) = Command::new("lrzip").arg("--version").output()
        && output.status.success()
    {
        return Some("lrzip");
    }
    None
}

#[cfg(feature = "rzip")]
fn rzip_binary() -> Option<&'static str> {
    use std::process::Command;

    if let Ok(output) = Command::new("rzip").arg("-V").output()
        && output.status.success()
    {
        return Some("rzip");
    }
    None
}

fn cpio_binary() -> Option<&'static str> {
    use std::process::Command;

    if let Ok(output) = Command::new("cpio").arg("--version").output()
        && output.status.success()
    {
        return Some("cpio");
    }
    None
}
// ============================================================
// xz tests
// ============================================================

fn xz_system_compress(filter_chain: &str, input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;

    let mut child = match std::process::Command::new("xz")
        .args(["-c", filter_chain])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run xz: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system xz compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}
fn xz_system_decode(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;

    let mut child = match std::process::Command::new("xz")
        .args(["-dc"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run xz: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system xz decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

#[path = "integration/ar.rs"]
mod ar_tests;
#[cfg(feature = "brotli")]
#[path = "integration/brotli.rs"]
mod brotli_tests;
#[path = "integration/bzip2.rs"]
mod bzip2_tests;
#[path = "integration/combined.rs"]
mod combined_tests;
#[path = "integration/cpio.rs"]
mod cpio_tests;
#[path = "integration/deb.rs"]
mod deb_tests;
#[path = "integration/deflate.rs"]
mod deflate_tests;
#[path = "integration/generated/mod.rs"]
mod generated_tests;
#[path = "integration/gzip.rs"]
mod gzip_tests;
#[path = "integration/lrzip.rs"]
mod lrzip_tests;
#[path = "integration/lz4.rs"]
mod lz4_tests;
#[path = "integration/lzip.rs"]
mod lzip_tests;
#[path = "integration/lzma_alone.rs"]
mod lzma_alone_tests;
#[path = "integration/lzo.rs"]
mod lzo_tests;
#[path = "integration/lzw.rs"]
mod lzw_tests;
#[path = "integration/rpm.rs"]
mod rpm_tests;
#[cfg(feature = "rzip")]
#[path = "integration/rzip.rs"]
mod rzip_tests;
#[cfg(feature = "sevenz")]
#[path = "integration/sevenz.rs"]
mod sevenz_tests;
#[path = "integration/snappy.rs"]
mod snappy_tests;
#[path = "integration/squashfs.rs"]
mod squashfs_tests;

#[cfg(feature = "mscab")]
#[path = "integration/mscab.rs"]
mod mscab_tests;

#[path = "integration/tar.rs"]
mod tar_tests;
#[path = "integration/xz.rs"]
mod xz_tests;
#[cfg(feature = "zim")]
#[path = "integration/zim.rs"]
mod zim_tests;
#[cfg(feature = "zip")]
#[path = "integration/zip.rs"]
mod zip_tests;
#[path = "integration/zlib.rs"]
mod zlib_tests;
#[path = "integration/zpaq.rs"]
mod zpaq_tests;
#[path = "integration/zstd.rs"]
mod zstd_tests;
