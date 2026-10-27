#[cfg(feature = "ar")]
use archive::archive::ar;
#[cfg(feature = "cpio")]
use archive::archive::cpio;
#[cfg(feature = "cramfs")]
use archive::archive::cramfs;
#[cfg(feature = "crx3")]
use archive::archive::crx3;
#[cfg(feature = "deb")]
use archive::archive::deb;
#[cfg(feature = "erofs")]
use archive::archive::erofs;
#[cfg(feature = "git-pack")]
use archive::archive::git_pack;
#[cfg(feature = "iso9660")]
use archive::archive::iso9660;
#[cfg(feature = "mscfb")]
use archive::archive::mscfb;
#[cfg(feature = "pea")]
use archive::archive::pea;
#[cfg(feature = "romfs")]
use archive::archive::romfs;
#[cfg(feature = "rpm")]
use archive::archive::rpm;
#[cfg(feature = "sevenz")]
use archive::archive::sevenz;
#[cfg(feature = "squashfs")]
use archive::archive::squashfs;
#[cfg(feature = "tar")]
use archive::archive::tar;
#[cfg(feature = "zip")]
use archive::archive::zip;
#[cfg(feature = "zpaq")]
use archive::archive::zpaq;
#[cfg(feature = "brotli")]
use archive::compress::brotli;
#[cfg(feature = "bzip2")]
use archive::compress::bzip2;
#[cfg(feature = "cmpsc")]
use archive::compress::cmpsc;
#[cfg(feature = "deflate")]
use archive::compress::deflate;
#[cfg(feature = "fastlz")]
use archive::compress::fastlz;
#[cfg(feature = "gzip")]
use archive::compress::gzip;
#[cfg(feature = "lrzip")]
use archive::compress::lrzip;
#[cfg(feature = "lz4")]
use archive::compress::lz4;
#[cfg(feature = "lzf")]
use archive::compress::lzf;
#[cfg(feature = "lzip")]
use archive::compress::lzip;
#[cfg(feature = "lzma-alone")]
use archive::compress::lzma_alone;
#[cfg(feature = "lzo")]
use archive::compress::lzo;
#[cfg(feature = "lzrw1")]
use archive::compress::lzrw1;
#[cfg(feature = "lzrw1a")]
use archive::compress::lzrw1a;
#[cfg(feature = "lzrw2")]
use archive::compress::lzrw2;
#[cfg(feature = "lzrw3")]
use archive::compress::lzrw3;
#[cfg(feature = "lzrw3a")]
use archive::compress::lzrw3a;
#[cfg(feature = "lzs")]
use archive::compress::lzs;
#[cfg(feature = "lzw")]
use archive::compress::lzw;
#[cfg(feature = "lzxd")]
use archive::compress::lzxd;
#[cfg(feature = "mppc")]
use archive::compress::mppc;
#[cfg(feature = "rzip")]
use archive::compress::rzip;
#[cfg(feature = "snappy")]
use archive::compress::snappy;
#[cfg(feature = "vcdiff")]
use archive::compress::vcdiff;
#[cfg(feature = "xca")]
use archive::compress::xca;
#[cfg(feature = "xz")]
use archive::compress::xz;
#[cfg(feature = "zlib")]
use archive::compress::zlib;
#[cfg(feature = "zstd")]
use archive::compress::zstd;
#[cfg(feature = "zx0")]
use archive::compress::zx0;
#[cfg(feature = "zx1")]
use archive::compress::zx1;
#[cfg(feature = "zx2")]
use archive::compress::zx2;
#[cfg(feature = "zx5")]
use archive::compress::zx5;
#[cfg(feature = "ascii85")]
use archive::encoding::ascii85;
#[cfg(feature = "binhex")]
use archive::encoding::binhex;
#[cfg(feature = "macbinary")]
use archive::encoding::macbinary;
#[cfg(feature = "uuencode")]
use archive::encoding::uuencode;
#[cfg(feature = "yenc")]
use archive::encoding::yenc;

/// Create a unique temporary directory for an integration test.
///
/// Tests must not share fixed paths under `/tmp`: the integration test
/// binary runs tests in parallel, and `cargo nextest` also runs different
/// test binaries concurrently.
#[allow(dead_code)]
fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "archive_test_{prefix}_{}_{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[allow(dead_code)]
fn require_external_tools() -> bool {
    std::env::var_os("ARCHIVE_REQUIRE_EXTERNAL_TOOLS").is_some()
}

#[allow(dead_code)]
fn command_available(name: &str, args: &[&str]) -> bool {
    let available = std::process::Command::new(name)
        .args(args)
        .output()
        .map(|output| output.status.success() || !output.stdout.is_empty())
        .unwrap_or(false);
    if !available && require_external_tools() {
        panic!("required external tool is unavailable: {name}");
    }
    available
}

#[allow(dead_code)]
fn python3_available() -> bool {
    command_available("python3", &["--version"])
}

/// In strict mode, fail once if any tool required by the test image is
/// missing. This prevents interop tests from silently skipping when the
/// environment is not the expected container image.
#[test]
fn required_external_tools_are_installed() {
    if !require_external_tools() {
        return;
    }
    const TOOLS: &[(&str, &[&str])] = &[
        ("7z", &["i"]),
        ("bsdtar", &["--version"]),
        ("tar", &["--version"]),
        ("gzip", &["--version"]),
        ("bzip2", &["--version"]),
        ("xz", &["--version"]),
        ("lzip", &["--version"]),
        ("lz4", &["--version"]),
        ("lzop", &["--version"]),
        ("lrzip", &["--version"]),
        ("cpio", &["--version"]),
        ("zip", &["-v"]),
        ("unzip", &["-v"]),
        ("zstd", &["--version"]),
        ("brotli", &["--version"]),
        ("python3", &["--version"]),
        ("git", &["--version"]),
        ("unar", &["--version"]),
        ("lhasa", &["--version"]),
        ("cabextract", &["-v"]),
        ("mksquashfs", &["-version"]),
        ("unsquashfs", &["-version"]),
        ("compress", &["-V"]),
        ("rzip", &["-V"]),
    ];
    for &(name, args) in TOOLS {
        assert!(
            command_available(name, args),
            "required external tool is unavailable: {name}"
        );
    }
}

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
    if require_external_tools() {
        panic!("required external tool is unavailable: 7z/7zz/7zr");
    }
    None
}
// ============================================================
// lrzip tests
// ============================================================

#[allow(dead_code)]
fn lrzip_binary() -> Option<&'static str> {
    use std::process::Command;

    if let Ok(output) = Command::new("lrzip").arg("--version").output()
        && output.status.success()
    {
        return Some("lrzip");
    }
    if require_external_tools() {
        panic!("required external tool is unavailable: lrzip");
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
    if require_external_tools() {
        panic!("required external tool is unavailable: rzip");
    }
    None
}

#[allow(dead_code)]
fn cpio_binary() -> Option<&'static str> {
    use std::process::Command;

    if let Ok(output) = Command::new("cpio").arg("--version").output()
        && output.status.success()
    {
        return Some("cpio");
    }
    if require_external_tools() {
        panic!("required external tool is unavailable: cpio");
    }
    None
}
// ============================================================
// xz tests
// ============================================================

#[cfg(feature = "xz")]
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if require_external_tools() {
                panic!("required external tool is unavailable: xz");
            }
            return None;
        }
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
#[cfg(feature = "xz")]
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if require_external_tools() {
                panic!("required external tool is unavailable: xz");
            }
            return None;
        }
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

#[cfg(feature = "ar")]
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
#[cfg(feature = "bzip2")]
#[path = "integration/bzip2.rs"]
mod bzip2_tests;
#[cfg(all(feature = "tar", feature = "cpio", feature = "gzip", feature = "zstd"))]
#[path = "integration/combined.rs"]
mod combined_tests;
#[cfg(feature = "cpio")]
#[path = "integration/cpio.rs"]
mod cpio_tests;
#[cfg(feature = "cramfs")]
#[path = "integration/cramfs.rs"]
mod cramfs_tests;
#[cfg(feature = "crx3")]
#[path = "integration/crx3.rs"]
mod crx3_tests;
#[cfg(feature = "deb")]
#[path = "integration/deb.rs"]
mod deb_tests;
#[cfg(feature = "deflate")]
#[path = "integration/deflate.rs"]
mod deflate_tests;
#[cfg(feature = "erofs")]
#[path = "integration/erofs.rs"]
mod erofs_tests;
// Generated module names come from fuzz failure signatures and are not
// required to be snake case.
#[allow(non_snake_case)]
#[path = "integration/generated/mod.rs"]
mod generated_tests;
#[cfg(feature = "gzip")]
#[path = "integration/gzip.rs"]
mod gzip_tests;
#[cfg(feature = "iso9660")]
#[path = "integration/iso9660.rs"]
mod iso9660_tests;
#[cfg(feature = "lha")]
#[path = "integration/lha.rs"]
mod lha_tests;
#[cfg(feature = "lrzip")]
#[path = "integration/lrzip.rs"]
mod lrzip_tests;
#[cfg(feature = "lz4")]
#[path = "integration/lz4.rs"]
mod lz4_tests;
#[cfg(feature = "lzip")]
#[path = "integration/lzip.rs"]
mod lzip_tests;
#[cfg(feature = "lzma-alone")]
#[path = "integration/lzma_alone.rs"]
mod lzma_alone_tests;
#[cfg(feature = "lzo")]
#[path = "integration/lzo.rs"]
mod lzo_tests;
#[cfg(feature = "lzw")]
#[path = "integration/lzw.rs"]
mod lzw_tests;
#[cfg(feature = "packbits")]
#[path = "integration/packbits.rs"]
mod packbits_tests;
#[cfg(feature = "pea")]
#[path = "integration/pea.rs"]
mod pea_tests;
#[cfg(feature = "romfs")]
#[path = "integration/romfs.rs"]
mod romfs_tests;
#[cfg(feature = "rpm")]
#[path = "integration/rpm.rs"]
mod rpm_tests;
#[cfg(feature = "rzip")]
#[path = "integration/rzip.rs"]
mod rzip_tests;
#[cfg(feature = "sevenz")]
#[path = "integration/sevenz.rs"]
mod sevenz_tests;
#[cfg(feature = "snappy")]
#[path = "integration/snappy.rs"]
mod snappy_tests;
#[cfg(feature = "squashfs")]
#[path = "integration/squashfs.rs"]
mod squashfs_tests;

#[cfg(feature = "mscab")]
#[path = "integration/mscab.rs"]
mod mscab_tests;
#[cfg(feature = "mscfb")]
#[path = "integration/mscfb.rs"]
mod mscfb_tests;

#[cfg(feature = "fastlz")]
#[path = "integration/fastlz.rs"]
mod fastlz_tests;

#[cfg(feature = "lzf")]
#[path = "integration/lzf.rs"]
mod lzf_tests;

#[cfg(feature = "lzsa")]
#[path = "integration/lzsa.rs"]
mod lzsa_tests;

#[cfg(feature = "lzxd")]
#[path = "integration/lzxd.rs"]
mod lzxd_tests;

#[cfg(feature = "cmpsc")]
#[path = "integration/cmpsc.rs"]
mod cmpsc_tests;

#[cfg(feature = "lzrw1")]
#[path = "integration/lzrw1.rs"]
mod lzrw1_tests;
#[cfg(feature = "lzrw1a")]
#[path = "integration/lzrw1a.rs"]
mod lzrw1a_tests;
#[cfg(feature = "lzrw2")]
#[path = "integration/lzrw2.rs"]
mod lzrw2_tests;
#[cfg(feature = "lzrw3")]
#[path = "integration/lzrw3.rs"]
mod lzrw3_tests;
#[cfg(feature = "lzrw3a")]
#[path = "integration/lzrw3a.rs"]
mod lzrw3a_tests;

#[cfg(feature = "git-pack")]
#[path = "integration/git_pack.rs"]
mod git_pack_tests;
#[cfg(feature = "xar")]
#[path = "integration/xar.rs"]
mod xar_tests;

#[cfg(feature = "lzs")]
#[path = "integration/lzs.rs"]
mod lzs_tests;
#[cfg(feature = "mppc")]
#[path = "integration/mppc.rs"]
mod mppc_tests;
#[cfg(feature = "mtree")]
#[path = "integration/mtree.rs"]
mod mtree_tests;
#[cfg(feature = "tar")]
#[path = "integration/tar.rs"]
mod tar_tests;
#[cfg(feature = "vcdiff")]
#[path = "integration/vcdiff.rs"]
mod vcdiff_tests;
#[cfg(feature = "zx0")]
#[path = "integration/zx0.rs"]
mod zx0_tests;
#[cfg(feature = "zx1")]
#[path = "integration/zx1.rs"]
mod zx1_tests;
#[cfg(feature = "zx2")]
#[path = "integration/zx2.rs"]
mod zx2_tests;
#[cfg(feature = "zx5")]
#[path = "integration/zx5.rs"]
mod zx5_tests;

#[cfg(feature = "xca")]
#[path = "integration/xca.rs"]
mod xca_tests;

#[cfg(feature = "xz")]
#[path = "integration/xz.rs"]
mod xz_tests;

#[cfg(feature = "ascii85")]
#[path = "integration/ascii85.rs"]
mod ascii85_tests;
#[cfg(feature = "binhex")]
#[path = "integration/binhex.rs"]
mod binhex_tests;
#[cfg(feature = "macbinary")]
#[path = "integration/macbinary.rs"]
mod macbinary_tests;
#[cfg(feature = "uuencode")]
#[path = "integration/uuencode.rs"]
mod uuencode_tests;
#[cfg(feature = "warc")]
#[path = "integration/warc.rs"]
mod warc_tests;
#[cfg(feature = "yenc")]
#[path = "integration/yenc.rs"]
mod yenc_tests;
#[cfg(feature = "zim")]
#[path = "integration/zim.rs"]
mod zim_tests;
#[cfg(feature = "zip")]
#[path = "integration/zip.rs"]
mod zip_tests;
#[cfg(feature = "zlib")]
#[path = "integration/zlib.rs"]
mod zlib_tests;
#[cfg(feature = "zpaq")]
#[path = "integration/zpaq.rs"]
mod zpaq_tests;
#[cfg(feature = "zstd")]
#[path = "integration/zstd_seekable.rs"]
mod zstd_seekable_tests;
#[cfg(feature = "zstd")]
#[path = "integration/zstd.rs"]
mod zstd_tests;
