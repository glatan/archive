#![cfg(all(
    feature = "ar",
    feature = "deb",
    feature = "rpm",
    feature = "squashfs",
    feature = "mscab",
    feature = "zim",
    feature = "mtree",
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
    feature = "zpaq",
    feature = "xca",
    feature = "lzf",
    feature = "fastlz",
    feature = "lzrw1",
    feature = "lzrw1a",
    feature = "lzrw2",
    feature = "lzrw3",
    feature = "lzrw3a",
    feature = "lzsa",
    feature = "zx0",
    feature = "zx1",
    feature = "zx2",
    feature = "zx5",
    feature = "lzxd",
    feature = "cmpsc"
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
use archive::compress::cmpsc;
use archive::compress::deflate;
use archive::compress::fastlz;
use archive::compress::gzip;
use archive::compress::lrzip;
use archive::compress::lz4;
use archive::compress::lzf;
use archive::compress::lzip;
use archive::compress::lzma_alone;
use archive::compress::lzo;
use archive::compress::lzrw1;
use archive::compress::lzrw1a;
use archive::compress::lzrw2;
use archive::compress::lzrw3;
use archive::compress::lzrw3a;
use archive::compress::lzw;
use archive::compress::lzxd;
#[cfg(feature = "rzip")]
use archive::compress::rzip;
use archive::compress::snappy;
use archive::compress::xca;
use archive::compress::xz;
use archive::compress::zlib;
use archive::compress::zstd;
use archive::compress::zx0;
use archive::compress::zx1;
use archive::compress::zx2;
use archive::compress::zx5;

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
#[cfg(feature = "arc")]
#[path = "integration/arc.rs"]
mod arc_tests;
#[cfg(feature = "arj")]
#[path = "integration/arj.rs"]
mod arj_tests;
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
#[cfg(feature = "lha")]
#[path = "integration/lha.rs"]
mod lha_tests;
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

#[path = "integration/fastlz.rs"]
mod fastlz_tests;

#[path = "integration/lzf.rs"]
mod lzf_tests;

#[path = "integration/lzsa.rs"]
mod lzsa_tests;

#[path = "integration/lzxd.rs"]
mod lzxd_tests;

#[path = "integration/cmpsc.rs"]
mod cmpsc_tests;

#[path = "integration/lzrw1.rs"]
mod lzrw1_tests;
#[path = "integration/lzrw1a.rs"]
mod lzrw1a_tests;
#[path = "integration/lzrw2.rs"]
mod lzrw2_tests;
#[path = "integration/lzrw3.rs"]
mod lzrw3_tests;
#[path = "integration/lzrw3a.rs"]
mod lzrw3a_tests;

#[cfg(feature = "mtree")]
#[path = "integration/mtree.rs"]
mod mtree_tests;
#[path = "integration/tar.rs"]
mod tar_tests;
#[path = "integration/zx0.rs"]
mod zx0_tests;
#[path = "integration/zx1.rs"]
mod zx1_tests;
#[path = "integration/zx2.rs"]
mod zx2_tests;
#[path = "integration/zx5.rs"]
mod zx5_tests;

#[path = "integration/xca.rs"]
mod xca_tests;

#[path = "integration/xz.rs"]
mod xz_tests;

#[cfg(feature = "warc")]
#[path = "integration/warc.rs"]
mod warc_tests;
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
#[path = "integration/zstd_seekable.rs"]
mod zstd_seekable_tests;
#[path = "integration/zstd.rs"]
mod zstd_tests;
