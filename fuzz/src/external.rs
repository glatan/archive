use crate::algorithms::Algorithm;
use std::collections::HashSet;
use std::fs;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
#[cfg(not(target_arch = "wasm32"))]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(not(target_arch = "wasm32"))]
use std::process::{Command, Output, Stdio};
#[cfg(not(target_arch = "wasm32"))]
use std::thread;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, Instant};

struct PipeToolSpec {
    compress_cmd: &'static str,
    compress_args: &'static [&'static str],
    decompress_cmd: &'static str,
    decompress_args: &'static [&'static str],
}

enum ExternalSpec {
    Pipe(PipeToolSpec),
    Archive(ArchiveSpec),
}

enum ArchiveSpec {
    Ar,
    Zip {
        extra_compress_args: &'static [&'static str],
    },
    SevenZ {
        extra_compress_args: &'static [&'static str],
    },
    Tar {
        format_args: &'static [&'static str],
    },
    Cpio {
        format: &'static str,
    },
    /// Upstream `zpaq` CLI (file-based JIDAC archiver). `method` is the
    /// `-mN` compression-level flag (0..5) selecting upstream model
    /// configs.
    Zpaq {
        method: &'static str,
    },
    Rzip,
}

const EXTERNAL_TOOL_TIMEOUT_SECS: u64 = 30;

const DEFLATE_COMPRESS_ARGS: &[&str] = &[
    "-c",
    "import sys, zlib\n\
data = sys.stdin.buffer.read()\n\
c = zlib.compressobj(6, zlib.DEFLATED, -15)\n\
sys.stdout.buffer.write(c.compress(data) + c.flush())\n",
];
const DEFLATE_DECOMPRESS_ARGS: &[&str] = &[
    "-c",
    "import sys, zlib\n\
sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(), -15))\n",
];
const ZLIB_COMPRESS_ARGS: &[&str] = &[
    "-c",
    "import sys, zlib\n\
sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read(), 6))\n",
];
const ZLIB_DECOMPRESS_ARGS: &[&str] = &[
    "-c",
    "import sys, zlib\n\
sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\n",
];
const GZIP_STORE_COMPRESS_ARGS: &[&str] = &[
    "-c",
    "import gzip, sys\n\
sys.stdout.buffer.write(gzip.compress(sys.stdin.buffer.read(), compresslevel=0, mtime=0))\n",
];
const GZIP_DECOMPRESS_ARGS: &[&str] = &[
    "-c",
    "import gzip, sys\n\
sys.stdout.buffer.write(gzip.decompress(sys.stdin.buffer.read()))\n",
];
const ASCII85_COMPRESS_ARGS: &[&str] = &[
    "-c",
    "import base64, sys\n\
sys.stdout.buffer.write(base64.a85encode(sys.stdin.buffer.read(), adobe=True))\n",
];
const ASCII85_DECOMPRESS_ARGS: &[&str] = &[
    "-c",
    "import base64, sys\n\
sys.stdout.buffer.write(base64.a85decode(sys.stdin.buffer.read(), adobe=True))\n",
];

const fn tool_spec(algo: Algorithm) -> Option<ExternalSpec> {
    match algo {
        Algorithm::Deflate => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "python3",
            compress_args: DEFLATE_COMPRESS_ARGS,
            decompress_cmd: "python3",
            decompress_args: DEFLATE_DECOMPRESS_ARGS,
        })),
        Algorithm::Gzip => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "gzip",
            compress_args: &["-c"],
            decompress_cmd: "gzip",
            decompress_args: &["-dc"],
        })),
        Algorithm::GzipFast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "gzip",
            compress_args: &["-1", "-c"],
            decompress_cmd: "gzip",
            decompress_args: &["-dc"],
        })),
        Algorithm::GzipStore => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "python3",
            compress_args: GZIP_STORE_COMPRESS_ARGS,
            decompress_cmd: "python3",
            decompress_args: GZIP_DECOMPRESS_ARGS,
        })),
        Algorithm::Zstd => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "zstd",
            compress_args: &["-c"],
            decompress_cmd: "zstd",
            decompress_args: &["-dc"],
        })),
        Algorithm::ZstdFast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "zstd",
            compress_args: &["-1", "-c"],
            decompress_cmd: "zstd",
            decompress_args: &["-dc"],
        })),
        Algorithm::ZstdBest => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "zstd",
            compress_args: &["-19", "-c"],
            decompress_cmd: "zstd",
            decompress_args: &["-dc"],
        })),
        Algorithm::ZstdNoChecksum => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "zstd",
            compress_args: &["--no-check", "-c"],
            decompress_cmd: "zstd",
            decompress_args: &["-dc"],
        })),
        Algorithm::ZstdDict => None,
        Algorithm::Bzip2 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "bzip2",
            compress_args: &["-c"],
            decompress_cmd: "bzip2",
            decompress_args: &["-dc"],
        })),
        Algorithm::Bzip2Fast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "bzip2",
            compress_args: &["-1", "-c"],
            decompress_cmd: "bzip2",
            decompress_args: &["-dc"],
        })),
        Algorithm::Bzip2Best => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "bzip2",
            compress_args: &["-9", "-c"],
            decompress_cmd: "bzip2",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lzip => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzip",
            compress_args: &["-c"],
            decompress_cmd: "lzip",
            decompress_args: &["-dc"],
        })),
        Algorithm::LzipFast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzip",
            compress_args: &["-0", "-c"],
            decompress_cmd: "lzip",
            decompress_args: &["-dc"],
        })),
        Algorithm::LzipBest => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzip",
            compress_args: &["-9", "-c"],
            decompress_cmd: "lzip",
            decompress_args: &["-dc"],
        })),
        Algorithm::LzipDict => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzip",
            compress_args: &["-s64KiB", "-c"],
            decompress_cmd: "lzip",
            decompress_args: &["-dc"],
        })),
        Algorithm::LzmaAlone => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--format=lzma", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["--format=lzma", "-dc"],
        })),
        Algorithm::Xz => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzFast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["-0", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzBest => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["-9", "-e", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzDelta => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--delta=dist=4", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzX86 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--x86", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzArm64 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--arm64", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzPpc => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--powerpc", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzIa64 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--ia64", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzSparc => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--sparc", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzArm => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--arm", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzArmThumb => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--armthumb", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::XzRiscV => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "xz",
            compress_args: &["--check=crc32", "--riscv", "--lzma2", "-c"],
            decompress_cmd: "xz",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lzw => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "compress",
            compress_args: &["-c", "-f"],
            decompress_cmd: "uncompress",
            decompress_args: &["-c"],
        })),
        Algorithm::LzwBits9 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "compress",
            compress_args: &["-b", "9", "-c", "-f"],
            decompress_cmd: "uncompress",
            decompress_args: &["-c"],
        })),
        Algorithm::Lz4 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lz4",
            compress_args: &["-c"],
            decompress_cmd: "lz4",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lz4Fast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lz4",
            compress_args: &["-1", "-c"],
            decompress_cmd: "lz4",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lz4Best => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lz4",
            compress_args: &["-12", "-c"],
            decompress_cmd: "lz4",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lz4SmallBlock => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lz4",
            compress_args: &["-c"],
            decompress_cmd: "lz4",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lz4Block | Algorithm::Lz4Dict => None,
        Algorithm::Lz4Legacy => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lz4",
            compress_args: &["-l", "-c"],
            decompress_cmd: "lz4",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lz4BlockDependent => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lz4",
            compress_args: &["-BD", "-c"],
            decompress_cmd: "lz4",
            decompress_args: &["-dc"],
        })),
        Algorithm::Lzo => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzop",
            compress_args: &["-c"],
            decompress_cmd: "lzop",
            decompress_args: &["-dc"],
        })),
        Algorithm::LzoFast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzop",
            compress_args: &["-1", "-c"],
            decompress_cmd: "lzop",
            decompress_args: &["-dc"],
        })),
        Algorithm::LzoBest => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lzop",
            compress_args: &["-9", "-c"],
            decompress_cmd: "lzop",
            decompress_args: &["-dc"],
        })),
        // Stdin lrzip sizes its buffers from detected RAM and one backend
        // overhead per CPU. On a large host that exceeds the fuzz-process cap
        // and the tool reports `Out of memory` before the decoder runs.
        // `-w 1` is a 100MB window, `-p 1` is one thread, `-m 18` is 1.8GB
        // of nominal RAM (hundreds of MB). `LRZIP=NOCONFIG` is set at spawn.
        Algorithm::LrzipLzma => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lrzip",
            compress_args: &["-w", "1", "-p", "1", "-m", "18", "--lzma"],
            decompress_cmd: "lrzip",
            decompress_args: &["-d", "-p", "1", "-m", "18"],
        })),
        Algorithm::LrzipBzip2 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lrzip",
            compress_args: &["-w", "1", "-p", "1", "-m", "18", "-b"],
            decompress_cmd: "lrzip",
            decompress_args: &["-d", "-p", "1", "-m", "18"],
        })),
        Algorithm::LrzipGzip => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lrzip",
            compress_args: &["-w", "1", "-p", "1", "-m", "18", "-g"],
            decompress_cmd: "lrzip",
            decompress_args: &["-d", "-p", "1", "-m", "18"],
        })),
        Algorithm::LrzipLzo => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lrzip",
            compress_args: &["-w", "1", "-p", "1", "-m", "18", "-l"],
            decompress_cmd: "lrzip",
            decompress_args: &["-d", "-p", "1", "-m", "18"],
        })),
        Algorithm::LrzipNone => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lrzip",
            compress_args: &["-w", "1", "-p", "1", "-m", "18", "-n"],
            decompress_cmd: "lrzip",
            decompress_args: &["-d", "-p", "1", "-m", "18"],
        })),
        Algorithm::LrzipZpaq => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "lrzip",
            compress_args: &["-w", "1", "-p", "1", "-m", "18", "-z"],
            decompress_cmd: "lrzip",
            decompress_args: &["-d", "-p", "1", "-m", "18"],
        })),
        Algorithm::Brotli => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "brotli",
            compress_args: &["-c"],
            decompress_cmd: "brotli",
            decompress_args: &["-dc"],
        })),
        Algorithm::BrotliFast => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "brotli",
            compress_args: &["-1", "-c"],
            decompress_cmd: "brotli",
            decompress_args: &["-dc"],
        })),
        Algorithm::BrotliBest => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "brotli",
            compress_args: &["-q", "11", "-c"],
            decompress_cmd: "brotli",
            decompress_args: &["-dc"],
        })),
        // Metadata blocks are spec-valid but system brotli rejects them.
        Algorithm::BrotliMeta => None,
        Algorithm::Snappy => None,
        Algorithm::Rzip => Some(ExternalSpec::Archive(ArchiveSpec::Rzip)),
        Algorithm::Zlib => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "python3",
            compress_args: ZLIB_COMPRESS_ARGS,
            decompress_cmd: "python3",
            decompress_args: ZLIB_DECOMPRESS_ARGS,
        })),
        Algorithm::Zpaq => Some(ExternalSpec::Archive(ArchiveSpec::Zpaq { method: "-m1" })),
        Algorithm::ZpaqLevel2 => Some(ExternalSpec::Archive(ArchiveSpec::Zpaq { method: "-m3" })),
        Algorithm::ZpaqLevel3 => Some(ExternalSpec::Archive(ArchiveSpec::Zpaq { method: "-m5" })),
        Algorithm::ZpaqArchive => None,
        Algorithm::Ar | Algorithm::ArBsd => Some(ExternalSpec::Archive(ArchiveSpec::Ar)),
        Algorithm::Deb => None,
        Algorithm::Rpm => None,
        Algorithm::Squashfs => None,
        Algorithm::Mscab => None,
        Algorithm::Zim => None,
        Algorithm::Mtree => None,
        Algorithm::GitPack | Algorithm::GitPackDelta | Algorithm::GitPackSha256 => None,
        Algorithm::Xar => None,
        Algorithm::Warc => None,
        Algorithm::Lha
        | Algorithm::LhaLh4
        | Algorithm::LhaLh5
        | Algorithm::LhaLh6
        | Algorithm::LhaLh7
        | Algorithm::LhaLzs
        | Algorithm::LhaLz5
        | Algorithm::LhaPm1
        | Algorithm::LhaPm2 => None,
        Algorithm::Arj
        | Algorithm::Arj1
        | Algorithm::Arj2
        | Algorithm::Arj3
        | Algorithm::Arj4
        | Algorithm::ArjGarbled => None,
        Algorithm::Arc => None,
        Algorithm::Xpress | Algorithm::XpressHuff | Algorithm::Lznt1 => None,
        Algorithm::Lzf => None,
        Algorithm::Fastlz => None,
        Algorithm::PackBits => None,
        Algorithm::Zx0 | Algorithm::Zx1 | Algorithm::Zx2 | Algorithm::Zx5 => None,
        // xdelta3 requires a source file argument; plain-pipe external
        // interop is not wired, matching the other raw codecs.
        Algorithm::Vcdiff | Algorithm::VcdiffSrc => None,
        Algorithm::Mppc | Algorithm::MppcRdp4 | Algorithm::MppcRdp5 => None,
        Algorithm::Lzs => None,
        Algorithm::ZstdSeekable => None,
        Algorithm::Lzsa | Algorithm::Lzsa2 => None,
        Algorithm::Lzrw1 | Algorithm::Lzrw1a => None,
        Algorithm::Lzrw2 | Algorithm::Lzrw3 | Algorithm::Lzrw3a => None,
        Algorithm::Lzxd => None,
        Algorithm::Cmpsc => None,
        Algorithm::Zip => Some(ExternalSpec::Archive(ArchiveSpec::Zip {
            extra_compress_args: &["-q"],
        })),
        Algorithm::ZipStore => Some(ExternalSpec::Archive(ArchiveSpec::Zip {
            extra_compress_args: &["-0", "-q"],
        })),
        // Info-ZIP cannot produce or verify the remaining methods; they are
        // covered by the self and corrupt patterns.
        Algorithm::ZipBzip2
        | Algorithm::ZipZstd
        | Algorithm::ZipDeflate64
        | Algorithm::ZipLzma
        | Algorithm::ZipXz
        | Algorithm::ZipPpmd
        | Algorithm::ZipShrunk
        | Algorithm::ZipImplode
        | Algorithm::ZipReduce => None,
        Algorithm::SevenZ => Some(ExternalSpec::Archive(ArchiveSpec::SevenZ {
            extra_compress_args: &["-y"],
        })),
        Algorithm::SevenZCopy => Some(ExternalSpec::Archive(ArchiveSpec::SevenZ {
            extra_compress_args: &["-mx=0", "-y"],
        })),
        Algorithm::SevenZLzma => Some(ExternalSpec::Archive(ArchiveSpec::SevenZ {
            extra_compress_args: &["-m0=LZMA", "-y"],
        })),
        Algorithm::SevenZPpmd => Some(ExternalSpec::Archive(ArchiveSpec::SevenZ {
            extra_compress_args: &["-m0=PPMd", "-y"],
        })),
        Algorithm::SevenZDeflate => Some(ExternalSpec::Archive(ArchiveSpec::SevenZ {
            extra_compress_args: &["-m0=Deflate", "-y"],
        })),
        Algorithm::SevenZBzip2 => Some(ExternalSpec::Archive(ArchiveSpec::SevenZ {
            extra_compress_args: &["-m0=BZip2", "-y"],
        })),
        Algorithm::SevenZDeflate64
        | Algorithm::SevenZBrotli
        | Algorithm::SevenZX86
        | Algorithm::SevenZBcj2
        | Algorithm::SevenZDelta => None,
        Algorithm::TarGnu | Algorithm::TarUstar => {
            Some(ExternalSpec::Archive(ArchiveSpec::Tar { format_args: &[] }))
        }
        Algorithm::TarPax => Some(ExternalSpec::Archive(ArchiveSpec::Tar {
            format_args: &["--format=posix"],
        })),
        Algorithm::Cpio | Algorithm::CpioCrc => {
            Some(ExternalSpec::Archive(ArchiveSpec::Cpio { format: "newc" }))
        }
        Algorithm::CpioOdc => Some(ExternalSpec::Archive(ArchiveSpec::Cpio { format: "odc" })),
        Algorithm::CpioBin => Some(ExternalSpec::Archive(ArchiveSpec::Cpio { format: "bin" })),
        Algorithm::Ascii85 => Some(ExternalSpec::Pipe(PipeToolSpec {
            compress_cmd: "python3",
            compress_args: ASCII85_COMPRESS_ARGS,
            decompress_cmd: "python3",
            decompress_args: ASCII85_DECOMPRESS_ARGS,
        })),
        // No pipe-style external oracle exists for these formats; self and
        // corrupt patterns cover them.
        Algorithm::Cramfs
        | Algorithm::Romfs
        | Algorithm::Erofs
        | Algorithm::Iso9660
        | Algorithm::IsoRr
        | Algorithm::Mscfb
        | Algorithm::MscfbV4
        | Algorithm::Pea
        | Algorithm::PeaStore
        | Algorithm::PeaSha256
        | Algorithm::Crx3
        | Algorithm::Yenc
        | Algorithm::Uuencode
        | Algorithm::BinHex => None,
    }
}

/// Whether an external tool spec is wired for `algo` (regardless of whether
/// the binary is actually installed).
pub fn has_tool_spec(algo: Algorithm) -> bool {
    tool_spec(algo).is_some()
}

pub fn check_available_tools() -> HashSet<Algorithm> {
    let mut available = HashSet::new();
    for &algo in Algorithm::ALL {
        if is_available(algo) {
            available.insert(algo);
        }
    }
    available
}

pub fn compress(algo: Algorithm, data: &[u8]) -> Result<Vec<u8>, String> {
    match tool_spec(algo).ok_or_else(|| format!("No external tool for {algo}"))? {
        ExternalSpec::Pipe(spec) => run_pipe_tool(spec.compress_cmd, spec.compress_args, data),
        ExternalSpec::Archive(spec) => run_archive_compress(spec, data),
    }
}

pub fn decompress(algo: Algorithm, data: &[u8]) -> Result<Vec<u8>, String> {
    match tool_spec(algo).ok_or_else(|| format!("No external tool for {algo}"))? {
        ExternalSpec::Pipe(spec) => run_pipe_tool(spec.decompress_cmd, spec.decompress_args, data),
        ExternalSpec::Archive(spec) => run_archive_decompress(spec, data),
    }
}

fn is_available(algo: Algorithm) -> bool {
    match tool_spec(algo) {
        Some(ExternalSpec::Pipe(spec)) => {
            which_exists(spec.compress_cmd) && which_exists(spec.decompress_cmd)
        }
        Some(ExternalSpec::Archive(ArchiveSpec::Ar)) => which_exists("ar"),
        Some(ExternalSpec::Archive(ArchiveSpec::Zip { .. })) => {
            which_exists("zip") && which_exists("unzip")
        }
        Some(ExternalSpec::Archive(ArchiveSpec::SevenZ { .. })) => sevenz_binary().is_some(),
        Some(ExternalSpec::Archive(ArchiveSpec::Tar { .. })) => which_exists("tar"),
        Some(ExternalSpec::Archive(ArchiveSpec::Cpio { .. })) => which_exists("cpio"),
        Some(ExternalSpec::Archive(ArchiveSpec::Zpaq { .. })) => which_exists("zpaq"),
        Some(ExternalSpec::Archive(ArchiveSpec::Rzip)) => which_exists("rzip"),
        None => false,
    }
}

fn which_exists(cmd: &str) -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Command::new("which")
            .arg(cmd)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
    #[cfg(target_arch = "wasm32")]
    {
        execute_tool("which", &[cmd], None, None).is_ok_and(|output| output.success)
    }
}

/// Send SIGKILL to every process in the given process group.
///
/// Called after a child exits to clean up any worker processes it spawned.
/// Workers that inherited the child's stdout/stderr pipe write ends keep those
/// pipes open until they exit; killing the process group closes those write
/// ends so that drain threads can get EOF and terminate.
///
/// Errors are ignored: if the group is already empty the `kill` command exits
/// with a non-zero status, which we discard with `.ok()`.
#[cfg(not(target_arch = "wasm32"))]
fn kill_process_group(pgid: u32) {
    Command::new("kill")
        .args(["-9", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok();
}

/// Wait for `child` to exit, collecting its stdout/stderr, with a hard timeout.
///
/// Design notes:
/// - stdout/stderr are drained in background threads to prevent pipe deadlock
///   (child fills the ~64 KB pipe buffer, blocks on write, never exits).
/// - The child must have been spawned with `.process_group(0)` so it gets its
///   own process group (PGID == child PID).  After the child exits we kill the
///   entire process group to ensure any worker processes it spawned also die,
///   closing their copies of the pipe write ends and unblocking drain threads.
/// - All paths join the drain threads before returning (no detached threads
///   leaking open file descriptors into future child spawns).
#[cfg(not(target_arch = "wasm32"))]
fn wait_timeout(
    mut child: std::process::Child,
    cmd: &str,
    timeout: Duration,
) -> Result<Output, String> {
    let pgid = child.id(); // process_group(0) was set; PGID == child PID

    let stdout_handle = child.stdout.take().map(|mut out| {
        thread::spawn(move || -> Vec<u8> {
            let mut buf = Vec::new();
            out.read_to_end(&mut buf).ok();
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut err| {
        thread::spawn(move || -> Vec<u8> {
            let mut buf = Vec::new();
            err.read_to_end(&mut buf).ok();
            buf
        })
    });

    let start = Instant::now();
    let poll_result: Result<std::process::ExitStatus, String> = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Child exited and has been reaped by try_wait().
                // Kill its process group so that any workers it spawned also
                // die and release their copies of the pipe write ends.
                kill_process_group(pgid);
                break Ok(status);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    child.kill().ok();
                    kill_process_group(pgid);
                    child.wait().ok();
                    break Err(format!("{cmd} timed out after {}s", timeout.as_secs()));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                child.kill().ok();
                kill_process_group(pgid);
                child.wait().ok();
                break Err(format!("{cmd}: wait failed: {e}"));
            }
        }
    };

    // Join drain threads in all paths.  kill_process_group() has already been
    // called so all write ends of the pipes are closed; read_to_end() finishes
    // quickly and join() returns without blocking.
    let stdout = stdout_handle
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = stderr_handle
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();

    match poll_result {
        Ok(status) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        Err(e) => Err(e),
    }
}

/// Soft address-space cap for one external tool, in KiB (`ulimit -v`).
///
/// The fuzz process keeps its own soft cap (`FUZZ_AS_KB`, 2GiB) so a corrupt
/// decoder cannot reserve a multi-gigabyte model and get the host OOM-killed.
/// Tool children raise their soft limit to this value instead of keeping the
/// fuzz cap. 4GiB is enough for the bounded `lrzip` invocation and stays small
/// enough that three parallel fuzz processes cannot each allocate a buffer
/// sized to host RAM.
#[cfg(not(target_arch = "wasm32"))]
const EXTERNAL_TOOL_AS_KB: u64 = 4 * 1024 * 1024;

/// Build a command that runs `cmd` under [`EXTERNAL_TOOL_AS_KB`].
///
/// `ulimit` is a shell builtin, so the spawned process is a shell that raises
/// its own soft limit and then `exec`s `cmd`. The hard limit is left alone:
/// `ulimit -S` can raise the soft limit only up to the hard limit inherited
/// from the fuzz process. `lrzip` also ignores `lrzip.conf`, which can set a
/// window above `-w`.
#[cfg(not(target_arch = "wasm32"))]
fn tool_command(cmd: &str) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!(
            "ulimit -S -v {EXTERNAL_TOOL_AS_KB} && exec \"$0\" \"$@\""
        ))
        .arg(cmd);
    if cmd == "lrzip" {
        command.env("LRZIP", "NOCONFIG");
    }
    command
}

fn run_pipe_tool(cmd: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>, String> {
    let output = execute_tool(cmd, args, None, Some(input))?;
    if !output.success {
        return Err(format!(
            "{cmd} exited with {}: {}",
            output.status_display,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn run_archive_compress(spec: ArchiveSpec, data: &[u8]) -> Result<Vec<u8>, String> {
    let temp = TempDir::new("archive-fuzz-external-compress")?;
    let input_name = archive_entry_name();
    let input_path = temp.path().join(input_name);
    fs::write(&input_path, data).map_err(|e| format!("write temp input failed: {e}"))?;

    let archive_path = match &spec {
        ArchiveSpec::Ar => temp.path().join("sample.a"),
        ArchiveSpec::Zip { .. } => temp.path().join("sample.zip"),
        ArchiveSpec::SevenZ { .. } => temp.path().join("sample.7z"),
        ArchiveSpec::Tar { .. } => temp.path().join("sample.tar"),
        ArchiveSpec::Cpio { .. } => temp.path().join("sample.cpio"),
        ArchiveSpec::Zpaq { .. } => temp.path().join("sample.zpaq"),
        ArchiveSpec::Rzip => temp.path().join("sample.rz"),
    };

    let archive_name = archive_path.file_name().unwrap().to_str().unwrap();
    match spec {
        ArchiveSpec::Ar => {
            run_command_in_dir("ar", &["rcs", archive_name, input_name], temp.path())?
        }
        ArchiveSpec::Zip {
            extra_compress_args,
        } => {
            let mut args: Vec<&str> = extra_compress_args.to_vec();
            args.push(archive_name);
            args.push(input_name);
            run_command_in_dir("zip", &args, temp.path())?
        }
        ArchiveSpec::SevenZ {
            extra_compress_args,
        } => {
            let binary = sevenz_binary().ok_or("No 7z binary found")?;
            let mut args: Vec<&str> = vec!["a"];
            args.extend_from_slice(extra_compress_args);
            args.push(archive_name);
            args.push(input_name);
            run_command_in_dir(binary, &args, temp.path())?;
        }
        ArchiveSpec::Tar { format_args } => {
            let mut args: Vec<&str> = format_args.to_vec();
            args.extend_from_slice(&["-cf", archive_name, input_name]);
            run_command_in_dir("tar", &args, temp.path())?
        }
        ArchiveSpec::Cpio { format } => {
            let archive_path_str = archive_path.to_str().ok_or("invalid archive path")?;
            let shell_cmd = format!(
                "cd {} && echo {} | cpio -o -H {} > {}",
                temp.path().display(),
                input_name,
                format,
                archive_path_str
            );
            run_command_in_dir("sh", &["-c", &shell_cmd], temp.path())?
        }
        ArchiveSpec::Zpaq { method } => {
            // -threads 1 for deterministic single-block output.
            run_command_in_dir(
                "zpaq",
                &["a", archive_name, input_name, method, "-threads", "1"],
                temp.path(),
            )?
        }
        ArchiveSpec::Rzip => {
            let archive_str = archive_path.to_str().ok_or("invalid archive path")?;
            let input_str = input_path.to_str().ok_or("invalid input path")?;
            run_command_in_dir(
                "rzip",
                &["-k", "-f", "-o", archive_str, input_str],
                temp.path(),
            )?
        }
    }

    fs::read(archive_path).map_err(|e| format!("read temp archive failed: {e}"))
}

fn run_archive_decompress(spec: ArchiveSpec, data: &[u8]) -> Result<Vec<u8>, String> {
    let temp = TempDir::new("archive-fuzz-external-decompress")?;
    let archive_path = match &spec {
        ArchiveSpec::Ar => temp.path().join("sample.a"),
        ArchiveSpec::Zip { .. } => temp.path().join("sample.zip"),
        ArchiveSpec::SevenZ { .. } => temp.path().join("sample.7z"),
        ArchiveSpec::Tar { .. } => temp.path().join("sample.tar"),
        ArchiveSpec::Cpio { .. } => temp.path().join("sample.cpio"),
        ArchiveSpec::Zpaq { .. } => temp.path().join("sample.zpaq"),
        ArchiveSpec::Rzip => temp.path().join("sample.rz"),
    };
    fs::write(&archive_path, data).map_err(|e| format!("write temp archive failed: {e}"))?;

    let archive_str = archive_path.to_str().unwrap();
    match spec {
        ArchiveSpec::Ar => {
            run_command_capture("ar", &["p", archive_str, archive_entry_name()], temp.path())
        }
        ArchiveSpec::Zip { .. } => run_command_capture(
            "unzip",
            &["-p", archive_str, archive_entry_name()],
            temp.path(),
        ),
        ArchiveSpec::SevenZ { .. } => {
            let binary = sevenz_binary().ok_or("No 7z binary found")?;
            run_command_capture(
                binary,
                &["e", "-so", archive_str, archive_entry_name()],
                temp.path(),
            )
        }
        ArchiveSpec::Tar { .. } => run_command_capture(
            "tar",
            &["-xf", archive_str, "-O", archive_entry_name()],
            temp.path(),
        ),
        ArchiveSpec::Cpio { .. } => {
            let shell_cmd = format!(
                "cd {} && cpio -i --to-stdout {} < {}",
                temp.path().display(),
                archive_entry_name(),
                archive_str,
            );
            run_command_capture("sh", &["-c", &shell_cmd], temp.path())
        }
        ArchiveSpec::Zpaq { .. } => {
            run_command_in_dir("zpaq", &["x", archive_str, "-threads", "1"], temp.path())?;
            fs::read(temp.path().join("sample"))
                .map_err(|e| format!("read extracted file failed: {e}"))
        }
        ArchiveSpec::Rzip => {
            let decoded = temp.path().join("decoded.bin");
            let decoded_str = decoded.to_str().ok_or("invalid output path")?;
            run_command_in_dir(
                "rzip",
                &["-d", "-k", "-f", "-o", decoded_str, archive_str],
                temp.path(),
            )?;
            fs::read(decoded).map_err(|e| format!("read extracted file failed: {e}"))
        }
    }
}

fn run_command_in_dir(cmd: &str, args: &[&str], dir: &Path) -> Result<(), String> {
    let output = execute_tool(cmd, args, Some(dir), None)?;
    if !output.success {
        return Err(format!(
            "{cmd} exited with {}: {}",
            output.status_display,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn run_command_capture(cmd: &str, args: &[&str], dir: &Path) -> Result<Vec<u8>, String> {
    let output = execute_tool(cmd, args, Some(dir), None)?;
    if !output.success {
        return Err(format!(
            "{cmd} exited with {}: {}",
            output.status_display,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

struct ToolOutput {
    success: bool,
    #[allow(dead_code)]
    code: i32,
    status_display: String,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run `cmd` under the external-tool address-space cap.
///
/// On Unix this is a process group with `ulimit` and a hard timeout. On wasm32
/// the same work happens in the native host: WASI cannot exec host binaries or
/// signal a process group, so `fuzz_host::exec` crosses that boundary.
fn execute_tool(
    cmd: &str,
    args: &[&str],
    dir: Option<&Path>,
    stdin_data: Option<&[u8]>,
) -> Result<ToolOutput, String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        execute_tool_unix(
            cmd,
            args,
            dir,
            stdin_data,
            Duration::from_secs(EXTERNAL_TOOL_TIMEOUT_SECS),
        )
    }
    #[cfg(target_arch = "wasm32")]
    {
        execute_tool_wasm(cmd, args, dir, stdin_data)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn execute_tool_unix(
    cmd: &str,
    args: &[&str],
    dir: Option<&Path>,
    stdin_data: Option<&[u8]>,
    timeout: Duration,
) -> Result<ToolOutput, String> {
    let mut command = tool_command(cmd);
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    // Write stdin in a background thread so it runs concurrently with the
    // stdout/stderr drain threads that wait_timeout spawns immediately after.
    //
    // Without this, a deadlock is possible for large inputs:
    //   1. write_all fills the stdin pipe (64 KB) and blocks.
    //   2. The child reads stdin and writes to stdout; stdout fills and the
    //      child blocks on write.
    //   3. The child stops reading stdin; write_all never unblocks.
    //   4. wait_timeout is never reached, so no drain thread exists.
    //      Both sides block forever.
    command
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to spawn {cmd}: {e}"))?;

    let stdin_handle = stdin_data.and_then(|input| {
        let input_owned = input.to_vec();
        child.stdin.take().map(|mut stdin| {
            thread::spawn(move || {
                stdin.write_all(&input_owned).ok();
            })
        })
    });

    let output = wait_timeout(child, cmd, timeout);

    // Join in all paths. If wait_timeout killed the process group (timeout or
    // error), write_all fails with EPIPE and the thread returns quickly.
    if let Some(handle) = stdin_handle {
        handle.join().ok();
    }

    let output = output?;
    Ok(ToolOutput {
        success: output.status.success(),
        code: output.status.code().unwrap_or(-1),
        status_display: output.status.to_string(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(all(not(target_arch = "wasm32"), feature = "wasm-host"))]
#[allow(dead_code)]
pub(crate) fn execute_tool_packed(
    cmd: &str,
    args: &[&str],
    dir: Option<&Path>,
    stdin_data: Option<&[u8]>,
    timeout: Duration,
) -> Vec<u8> {
    match execute_tool_unix(cmd, args, dir, stdin_data, timeout) {
        Ok(output) => crate::host_proto::pack(
            true,
            output.code,
            &output.status_display,
            &output.stdout,
            &output.stderr,
        ),
        Err(err) => crate::host_proto::pack(false, -1, "", &[], err.as_bytes()),
    }
}

#[cfg(target_arch = "wasm32")]
fn execute_tool_wasm(
    cmd: &str,
    args: &[&str],
    dir: Option<&Path>,
    stdin_data: Option<&[u8]>,
) -> Result<ToolOutput, String> {
    let args_blob = args.join("\0");
    let dir_blob = dir
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stdin = stdin_data.unwrap_or(&[]);
    // 1MiB is enough for probes. A larger result returns only its length; the
    // host keeps the bytes and this loop copies them. The command runs once.
    let mut cap = 1024 * 1024;
    loop {
        let mut buf = vec![0u8; cap];
        let need = unsafe {
            host_exec(
                cmd.as_ptr(),
                cmd.len() as i32,
                args_blob.as_ptr(),
                args_blob.len() as i32,
                dir_blob.as_ptr(),
                dir_blob.len() as i32,
                stdin.as_ptr(),
                stdin.len() as i32,
                i32::from(stdin_data.is_none()),
                (EXTERNAL_TOOL_TIMEOUT_SECS * 1000) as i32,
                buf.as_mut_ptr(),
                cap as i32,
            )
        };
        if need < 0 {
            return Err(format!("Failed to spawn {cmd}: host exec failed"));
        }
        let need = need as usize;
        if need <= cap {
            let body = crate::host_proto::unpack(&buf[..need])?;
            if !body.finished {
                return Err(String::from_utf8_lossy(&body.stderr).into_owned());
            }
            return Ok(ToolOutput {
                // Signaled processes are packed with code -1. Exit code 0 is
                // the only success, matching `ExitStatus::success`.
                success: body.code == 0,
                code: body.code,
                status_display: body.status_display,
                stdout: body.stdout,
                stderr: body.stderr,
            });
        }
        cap = need;
    }
}

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "fuzz_host")]
#[allow(clippy::too_many_arguments)]
unsafe extern "C" {
    #[link_name = "exec"]
    fn host_exec(
        cmd: *const u8,
        cmd_len: i32,
        args: *const u8,
        args_len: i32,
        dir: *const u8,
        dir_len: i32,
        stdin: *const u8,
        stdin_len: i32,
        stdin_null: i32,
        timeout_ms: i32,
        out: *mut u8,
        out_cap: i32,
    ) -> i32;
}

const fn archive_entry_name() -> &'static str {
    "fuzz_test"
}

/// Return the name of the available 7z binary, probing once and caching the result.
///
/// Without caching, every 7z compress/decompress operation would spawn `7z i`
/// to discover the binary name — O(n_tests) extra process spawns.  With
/// OnceLock the probe runs exactly once per process lifetime.
fn sevenz_binary() -> Option<&'static str> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Option<&'static str>> = OnceLock::new();
    *CACHE.get_or_init(|| {
        ["7z", "7zz", "7zr"].into_iter().find(|&candidate| {
            #[cfg(not(target_arch = "wasm32"))]
            {
                Command::new(candidate)
                    .arg("i")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
            }
            #[cfg(target_arch = "wasm32")]
            {
                execute_tool(candidate, &["i"], None, None).is_ok_and(|output| output.success)
            }
        })
    })
}

struct TempDir {
    path: PathBuf,
}

fn temp_base() -> PathBuf {
    #[cfg(target_arch = "wasm32")]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::temp_dir()
    }
}

fn temp_dir_owner() -> u32 {
    // `std::process::id` aborts on wasm32 (`no pids on this platform`).
    // The guest is one process; the nanosecond stamp and the attempt
    // counter keep the directory name unique.
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::process::id()
    }
}

impl TempDir {
    fn new(prefix: &str) -> Result<Self, String> {
        let base = temp_base();
        for attempt in 0..1000u32 {
            let path = base.join(format!(
                "{prefix}-{}-{}-{}",
                temp_dir_owner(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
                attempt
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(format!("create temp dir failed: {err}")),
            }
        }
        Err("could not allocate temp dir".to_string())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::TempDir;
    use std::os::unix::process::CommandExt;

    #[test]
    fn temp_dir_is_created() {
        let temp = TempDir::new("archive-fuzz-test").unwrap();
        assert!(temp.path().exists());
    }

    use super::{
        EXTERNAL_TOOL_AS_KB, ExternalSpec, run_command_capture, run_command_in_dir, run_pipe_tool,
        tool_spec, wait_timeout,
    };
    use crate::algorithms::Algorithm;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[test]
    fn wait_timeout_kills_hanging_process() {
        let child = Command::new("sleep")
            .arg("9999")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let result = wait_timeout(child, "sleep", Duration::from_millis(300));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("timed out"), "unexpected error: {err}");
    }

    #[test]
    fn wait_timeout_collects_stdout_from_fast_process() {
        let child = Command::new("echo")
            .arg("hello-fuzz")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let output = wait_timeout(child, "echo", Duration::from_secs(5)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello-fuzz\n");
    }

    #[test]
    fn run_command_in_dir_succeeds_for_true() {
        let temp = TempDir::new("archive-fuzz-test-cmd").unwrap();
        run_command_in_dir("true", &[], temp.path()).unwrap();
    }

    #[test]
    fn run_command_in_dir_reports_nonzero_exit() {
        let temp = TempDir::new("archive-fuzz-test-cmd-fail").unwrap();
        let err = run_command_in_dir("false", &[], temp.path()).unwrap_err();
        assert!(err.contains("exited with"), "unexpected error: {err}");
    }

    #[test]
    fn run_command_capture_returns_stdout() {
        let temp = TempDir::new("archive-fuzz-test-capture").unwrap();
        let out = run_command_capture("echo", &["capture-test"], temp.path()).unwrap();
        assert_eq!(out, b"capture-test\n");
    }

    #[test]
    #[ignore = "実際に sleep 9999 を起動して kill するため数秒かかる。CI では cargo test -- --ignored で実行する"]
    fn run_command_in_dir_times_out() {
        // Verify that a hanging command is killed and returns a timeout error.
        // process_group(0) is required: sh may spawn `sleep` as a subprocess
        // that inherits the stdout pipe write end.  Without process-group kill,
        // the drain thread blocks on sleep's open write end after sh is killed.
        let temp = TempDir::new("archive-fuzz-test-timeout").unwrap();
        let script_path = temp.path().join("hang.sh");
        std::fs::write(&script_path, "#!/bin/sh\nsleep 9999\n").unwrap();
        let child = Command::new("sh")
            .arg(&script_path)
            .current_dir(temp.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let result = wait_timeout(child, "sh", Duration::from_millis(300));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }

    /// A process that writes more than the pipe buffer (~64 KB) to stdout must
    /// not deadlock even though we don't read stdout from the main thread.
    #[test]
    fn wait_timeout_does_not_deadlock_on_large_stdout() {
        // `yes` writes an infinite stream; we kill it after 300 ms.
        // Without the drain thread this would deadlock: yes fills the pipe,
        // blocks on write, never exits, try_wait loops forever.
        let child = Command::new("yes")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let result = wait_timeout(child, "yes", Duration::from_millis(300));
        // Must return an error (timed out), not hang forever.
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }

    /// run_pipe_tool must not deadlock when the input is larger than the pipe
    /// buffer and the child echoes it back (stdin and stdout both fill simultaneously).
    ///
    /// `cat` is the minimal reproducer: it reads all of stdin and writes it to
    /// stdout.  For inputs larger than the OS pipe buffer (~64 KB), the old
    /// sequential write_all → wait_timeout approach would deadlock:
    ///   - write_all fills the stdin pipe and blocks.
    ///   - cat fills the stdout pipe and blocks (nobody is draining it yet).
    ///   - cat stops reading stdin; write_all never returns.
    ///   - wait_timeout is never reached; no drain thread is ever spawned.
    #[test]
    fn run_pipe_tool_does_not_deadlock_on_large_stdin_large_stdout() {
        let large_input = vec![0xab_u8; 256 * 1024]; // 256 KB — well above pipe buffer
        let result = run_pipe_tool("cat", &[], &large_input);
        assert!(
            result.is_ok(),
            "run_pipe_tool deadlocked or errored: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), large_input);
    }

    /// A process that writes to stderr must have that output captured and
    /// returned in the Output struct.
    #[test]
    fn wait_timeout_collects_stderr_from_process() {
        let child = Command::new("sh")
            .args(["-c", "echo stderr-marker >&2"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let output = wait_timeout(child, "sh", Duration::from_secs(5)).unwrap();
        assert!(output.status.success());
        assert!(
            output.stderr.windows(13).any(|w| w == b"stderr-marker"),
            "stderr not captured: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// When a pipe-tool exits with a non-zero status its stderr must appear in
    /// the returned error message so callers can diagnose what went wrong.
    #[test]
    fn run_pipe_tool_includes_stderr_in_error_message() {
        let err =
            run_pipe_tool("sh", &["-c", "echo tool-error >&2; exit 1"], b"input").unwrap_err();
        assert!(
            err.contains("tool-error"),
            "stderr not in error message: {err}"
        );
    }

    /// When the child exits before reading all of stdin the stdin write thread
    /// must receive EPIPE and return quickly — run_pipe_tool must not hang.
    ///
    /// Scenario: child exits immediately (`sh -c 'exit 0'`) without reading
    /// stdin.  The OS closes the pipe read end when the child exits.  The write
    /// thread's `write_all` returns EPIPE which is silently ignored via `.ok()`.
    #[test]
    fn run_pipe_tool_does_not_hang_when_child_ignores_stdin() {
        // Use a 256 KB input — well above the 64 KB pipe buffer — so write_all
        // would block if the read end were still open.
        let large_input = vec![0xcd_u8; 256 * 1024];
        // `sh -c 'exit 0'` exits immediately, returning success with empty stdout.
        let result = run_pipe_tool("sh", &["-c", "exit 0"], &large_input);
        // The child exits with status 0 and produces no output, so run_pipe_tool
        // succeeds and returns an empty Vec.
        assert!(
            result.is_ok(),
            "run_pipe_tool hung or errored: {:?}",
            result.err()
        );
        assert!(result.unwrap().is_empty());
    }

    /// A child that spawns a background subprocess which inherits the stdout
    /// write end must not cause wait_timeout to hang indefinitely.
    ///
    /// Without process-group kill: sh exits (zombie reaped), drain thread
    /// blocks in read_to_end() because the background sleep still holds the
    /// pipe write end open, join() never returns.
    ///
    /// With process-group kill: after sh exits, kill_process_group() sends
    /// SIGKILL to sleep, write end closes, drain thread gets EOF.
    #[test]
    fn wait_timeout_does_not_hang_when_child_spawns_subprocess_holding_pipe() {
        // sh spawns `sleep 60` in the background (inheriting stdout pipe),
        // then sh exits immediately.  sleep keeps the write end alive.
        let child = Command::new("sh")
            .args(["-c", "sleep 60 &"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0) // child gets its own process group; sleep inherits it
            .spawn()
            .unwrap();
        // sh exits quickly (exit 0); without process-group kill this hangs.
        let result = wait_timeout(child, "sh", Duration::from_secs(5));
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    #[test]
    fn lrzip_compress_uses_100mb_window() {
        for algo in [
            Algorithm::LrzipLzma,
            Algorithm::LrzipBzip2,
            Algorithm::LrzipGzip,
            Algorithm::LrzipLzo,
            Algorithm::LrzipNone,
            Algorithm::LrzipZpaq,
        ] {
            let Some(ExternalSpec::Pipe(spec)) = tool_spec(algo) else {
                panic!("{algo:?} has no pipe spec");
            };
            assert_eq!(spec.compress_cmd, "lrzip");
            assert!(
                spec.compress_args
                    .windows(2)
                    .any(|pair| pair == ["-w", "1"]),
                "{algo:?} compress args {:?} lack -w 1",
                spec.compress_args
            );
            assert!(
                spec.compress_args
                    .windows(2)
                    .any(|pair| pair == ["-p", "1"]),
                "{algo:?} compress args {:?} lack -p 1",
                spec.compress_args
            );
            assert!(
                spec.compress_args
                    .windows(2)
                    .any(|pair| pair == ["-m", "18"]),
                "{algo:?} compress args {:?} lack -m 18",
                spec.compress_args
            );
            assert_eq!(spec.decompress_args, &["-d", "-p", "1", "-m", "18"]);
        }
    }

    fn tool_soft_address_limit_bytes() -> u64 {
        let out = run_pipe_tool(
            "sh",
            &[
                "-c",
                "awk '/^Max address space/ { print $4 }' /proc/self/limits",
            ],
            b"",
        )
        .unwrap_or_else(|e| panic!("failed to read address limit: {e}"));
        let text = String::from_utf8(out).unwrap();
        text.trim()
            .parse()
            .unwrap_or_else(|_| panic!("unexpected limit text: {text:?}"))
    }

    #[test]
    fn external_tool_soft_address_limit_is_four_gib() {
        assert_eq!(tool_soft_address_limit_bytes(), EXTERNAL_TOOL_AS_KB * 1024);
    }

    /// The fuzz process lowers only its soft limit. A tool child must raise
    /// that soft limit to the tool cap. This spawns a fresh process under a
    /// soft limit below 4GiB so the assertion is not running in the shared
    /// `cargo test` process.
    #[test]
    fn external_tool_raises_soft_limit_above_parent() {
        if std::env::var_os("ARCHIVE_FUZZ_RLIMIT_PROBE").is_some() {
            assert_eq!(tool_soft_address_limit_bytes(), EXTERNAL_TOOL_AS_KB * 1024);
            std::process::exit(0);
        }

        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let vm_kb: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("VmSize:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        // Headroom for the probe process itself. Still below the tool cap.
        let parent_kb = vm_kb.saturating_add(1024 * 1024);
        assert!(
            parent_kb < EXTERNAL_TOOL_AS_KB,
            "test process VmSize {vm_kb}KiB leaves no gap under the tool cap"
        );

        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("ulimit -S -v {parent_kb} && exec \"$0\" \"$@\""))
            .arg(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::external_tool_raises_soft_limit_above_parent")
            .env("ARCHIVE_FUZZ_RLIMIT_PROBE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "probe failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
