//! Benchmark case catalog.
//!
//! Every user-facing format in `docs/spec/` is represented here. Formats
//! without a usable reference are still listed and measured on our side
//! when the CLI/helper dispatch supports them; the report marks the
//! reference column as N/A with the reason from `note`.

use crate::model::{
    Case, FAST, Kind, MEDIUM, OutputMode, RefCommand, RefSpec, SLOW, SizeClass, TINY,
};

const DISTRO: &str = "distro package (exact distro build flags not exposed)";

// ---------------------------------------------------------------------------
// Reference command helpers
// ---------------------------------------------------------------------------

const PY_ZLIB: &str = r#"
import sys, zlib
mode, kind, level, inp, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
data = open(inp, 'rb').read()
wbits = 15 if kind == 'zlib' else -15
if mode == 'encode':
    c = zlib.compressobj(level, zlib.DEFLATED, wbits)
    result = c.compress(data) + c.flush()
else:
    result = zlib.decompress(data, wbits)
open(out, 'wb').write(result)
"#;

#[allow(dead_code)]
const PY_UUENCODE: &str = r#"
import sys, binascii
mode, inp, out = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(inp, 'rb').read()
if mode == 'encode':
    result = bytearray()
    for i in range(0, len(data), 45):
        result += binascii.b2a_uu(data[i:i+45])
    result += b'`\n'
else:
    result = bytearray()
    for line in data.splitlines():
        if line in (b'`', b'`\r'):
            break
        result += binascii.a2b_uu(line)
open(out, 'wb').write(result)
"#;

#[allow(dead_code)]
const PY_ASCII85: &str = r#"
import sys, base64
mode, inp, out = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(inp, 'rb').read()
result = base64.a85encode(data) if mode == 'encode' else base64.a85decode(data)
open(out, 'wb').write(result)
"#;

fn cmd(program: &'static str, args: &'static [&'static str], output: OutputMode) -> RefCommand {
    RefCommand {
        program,
        args,
        output,
    }
}

fn gzip_ref() -> RefSpec {
    RefSpec {
        name: "GNU gzip",
        version: "1.15",
        binary_id: "gzip",
        build: DISTRO,
        encode: Some(cmd(
            "gzip",
            &["-6", "-n", "-c", "{input}"],
            OutputMode::Stdout,
        )),
        decode: Some(cmd("gzip", &["-dc", "{input}"], OutputMode::Stdout)),
    }
}

fn zstd_ref() -> RefSpec {
    RefSpec {
        name: "zstd",
        version: "1.5.7",
        binary_id: "zstd",
        build: DISTRO,
        encode: Some(cmd(
            "zstd",
            &[
                "-3",
                "--zstd=wlog=15",
                "--check",
                "-T1",
                "-q",
                "-c",
                "{input}",
            ],
            OutputMode::Stdout,
        )),
        decode: Some(cmd(
            "zstd",
            &["-d", "-q", "-c", "{input}"],
            OutputMode::Stdout,
        )),
    }
}

fn bzip2_ref() -> RefSpec {
    RefSpec {
        name: "bzip2",
        version: "1.0.8",
        binary_id: "bzip2",
        build: DISTRO,
        encode: Some(cmd("bzip2", &["-9", "-c", "{input}"], OutputMode::Stdout)),
        decode: Some(cmd("bzip2", &["-dc", "{input}"], OutputMode::Stdout)),
    }
}

fn lzip_ref() -> RefSpec {
    RefSpec {
        name: "GNU lzip",
        version: "1.26",
        binary_id: "lzip",
        build: DISTRO,
        encode: Some(cmd(
            "lzip",
            &["-6", "-s", "4096", "-c", "{input}"],
            OutputMode::Stdout,
        )),
        decode: Some(cmd("lzip", &["-dc", "{input}"], OutputMode::Stdout)),
    }
}

fn xz_ref() -> RefSpec {
    RefSpec {
        name: "XZ Utils",
        version: "5.8.4",
        binary_id: "xz",
        build: DISTRO,
        encode: Some(cmd(
            "xz",
            &["--lzma2=dict=4KiB", "-6", "-T1", "-c", "{input}"],
            OutputMode::Stdout,
        )),
        decode: Some(cmd("xz", &["-dc", "{input}"], OutputMode::Stdout)),
    }
}

fn lzma_ref() -> RefSpec {
    RefSpec {
        name: "XZ Utils (lzma-alone)",
        version: "5.8.4",
        binary_id: "xz",
        build: DISTRO,
        encode: Some(cmd(
            "xz",
            &[
                "--format=lzma",
                "--lzma1=dict=8MiB",
                "-6",
                "-T1",
                "-c",
                "{input}",
            ],
            OutputMode::Stdout,
        )),
        decode: Some(cmd(
            "xz",
            &["--format=lzma", "-dc", "{input}"],
            OutputMode::Stdout,
        )),
    }
}

fn lzw_ref() -> RefSpec {
    RefSpec {
        name: "ncompress",
        version: "5.0",
        binary_id: "compress",
        build: DISTRO,
        encode: Some(cmd("compress", &["-c", "{input}"], OutputMode::Stdout)),
        decode: Some(cmd("uncompress", &["-c", "{input}"], OutputMode::Stdout)),
    }
}

fn lz4_ref() -> RefSpec {
    RefSpec {
        name: "lz4",
        version: "1.10.0",
        binary_id: "lz4",
        build: DISTRO,
        encode: Some(cmd(
            "lz4",
            &["-1", "-B7", "-BX", "--content-size", "-c", "{input}"],
            OutputMode::Stdout,
        )),
        decode: Some(cmd("lz4", &["-dc", "{input}"], OutputMode::Stdout)),
    }
}

fn lzo_ref() -> RefSpec {
    RefSpec {
        name: "lzop",
        version: "1.04",
        binary_id: "lzop",
        build: DISTRO,
        encode: Some(cmd("lzop", &["-1", "-c", "{input}"], OutputMode::Stdout)),
        decode: Some(cmd("lzop", &["-dc", "{input}"], OutputMode::Stdout)),
    }
}

fn brotli_ref() -> RefSpec {
    RefSpec {
        name: "brotli",
        version: "1.2.0",
        binary_id: "brotli",
        build: DISTRO,
        encode: Some(cmd(
            "brotli",
            &["-q", "5", "-c", "{input}"],
            OutputMode::Stdout,
        )),
        decode: Some(cmd("brotli", &["-d", "-c", "{input}"], OutputMode::Stdout)),
    }
}

fn rzip_ref() -> RefSpec {
    RefSpec {
        name: "rzip",
        version: "2.1",
        binary_id: "rzip",
        build: DISTRO,
        encode: Some(cmd(
            "rzip",
            &["-6", "-o", "{output}", "{input}"],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "rzip",
            &["-d", "-o", "{output}", "{input}"],
            OutputMode::None,
        )),
    }
}

fn lrzip_ref() -> RefSpec {
    RefSpec {
        name: "lrzip",
        version: "0.660",
        binary_id: "lrzip",
        build: DISTRO,
        encode: Some(cmd(
            "lrzip",
            &[
                "-q", "-p", "1", "-L", "7", "--lzma", "-o", "{output}", "{input}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "lrzip",
            &["-q", "-d", "-o", "{output}", "{input}"],
            OutputMode::None,
        )),
    }
}

const PY_ZLIB_ENC_ZLIB: &[&str] = &["-c", PY_ZLIB, "encode", "zlib", "6", "{input}", "{output}"];
const PY_ZLIB_DEC_ZLIB: &[&str] = &["-c", PY_ZLIB, "decode", "zlib", "6", "{input}", "{output}"];
const PY_ZLIB_ENC_DEFLATE: &[&str] = &[
    "-c", PY_ZLIB, "encode", "deflate", "6", "{input}", "{output}",
];
const PY_ZLIB_DEC_DEFLATE: &[&str] = &[
    "-c", PY_ZLIB, "decode", "deflate", "6", "{input}", "{output}",
];

fn zlib_ref(kind: &'static str) -> RefSpec {
    RefSpec {
        name: "CPython zlib",
        version: "system Python 3 / zlib",
        binary_id: "python3",
        build: "CPython zlib module; zlib C library built by the distribution",
        encode: Some(cmd(
            "python3",
            if kind == "zlib" {
                PY_ZLIB_ENC_ZLIB
            } else {
                PY_ZLIB_ENC_DEFLATE
            },
            OutputMode::Arg,
        )),
        decode: Some(cmd(
            "python3",
            if kind == "zlib" {
                PY_ZLIB_DEC_ZLIB
            } else {
                PY_ZLIB_DEC_DEFLATE
            },
            OutputMode::Arg,
        )),
    }
}

#[allow(dead_code)]
fn uuencode_ref() -> RefSpec {
    RefSpec {
        name: "CPython binascii (uuencode)",
        version: "system Python 3",
        binary_id: "python3",
        build: "CPython stdlib binascii; distribution Python build",
        encode: Some(cmd(
            "python3",
            &["-c", PY_UUENCODE, "encode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd(
            "python3",
            &["-c", PY_UUENCODE, "decode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
    }
}

#[allow(dead_code)]
fn ascii85_ref() -> RefSpec {
    RefSpec {
        name: "CPython base64 (Ascii85)",
        version: "system Python 3",
        binary_id: "python3",
        build: "CPython stdlib base64; distribution Python build",
        encode: Some(cmd(
            "python3",
            &["-c", PY_ASCII85, "encode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd(
            "python3",
            &["-c", PY_ASCII85, "decode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
    }
}

// ---------------------------------------------------------------------------
// Archive reference commands
// ---------------------------------------------------------------------------

fn tar_ref() -> RefSpec {
    RefSpec {
        name: "GNU tar",
        version: "system tar",
        binary_id: "tar",
        build: DISTRO,
        encode: Some(cmd(
            "bash",
            &[
                "-c",
                "cd \"$(dirname \"$1\")\" && tar --format=ustar -cf \"$2\" \"$(basename \"$1\")\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "bash",
            &[
                "-c",
                "mkdir -p \"$2\" && tar -xf \"$1\" -C \"$2\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::Dir,
        )),
    }
}

fn cpio_ref() -> RefSpec {
    RefSpec {
        name: "GNU cpio",
        version: "system cpio",
        binary_id: "cpio",
        build: DISTRO,
        encode: Some(cmd(
            "bash",
            &[
                "-c",
                "cd \"$(dirname \"$1\")\" && find \"$(basename \"$1\")\" -print0 | cpio --null -o -H newc > \"$2\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "bash",
            &[
                "-c",
                "mkdir -p \"$2\" && cd \"$2\" && cpio -id --null < \"$1\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::Dir,
        )),
    }
}

fn ar_ref() -> RefSpec {
    RefSpec {
        name: "GNU ar",
        version: "system binutils",
        binary_id: "ar",
        build: DISTRO,
        encode: Some(cmd(
            "bash",
            &[
                "-c",
                "cd \"$(dirname \"$1\")\" && ar rcs \"$2\" $(find \"$(basename \"$1\")\" -type f | sort)",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "bash",
            &[
                "-c",
                "mkdir -p \"$2\" && cd \"$2\" && ar x \"$1\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::Dir,
        )),
    }
}

fn zip_ref() -> RefSpec {
    RefSpec {
        name: "Info-ZIP zip",
        version: "3.0",
        binary_id: "zip",
        build: DISTRO,
        encode: Some(cmd(
            "bash",
            &[
                "-c",
                "cd \"$(dirname \"$1\")\" && zip -q -6 -D -r \"$2\" \"$(basename \"$1\")\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "unzip",
            &["-q", "-o", "{input}", "-d", "{output}"],
            OutputMode::Dir,
        )),
    }
}

fn sevenz_ref() -> RefSpec {
    RefSpec {
        name: "7-Zip",
        version: "26.04",
        binary_id: "7z",
        build: DISTRO,
        encode: Some(cmd(
            "bash",
            &[
                "-c",
                "cd \"$(dirname \"$1\")\" && 7z a -t7z -m0=lzma2:d=8m -mx=5 -mmt=1 -bso0 -bsp0 \"$2\" \"$(basename \"$1\")\"",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "7z",
            &["x", "-y", "-bso0", "-bsp0", "-o{output}", "{input}"],
            OutputMode::Dir,
        )),
    }
}

fn zpaq_ref() -> RefSpec {
    RefSpec {
        name: "zpaq",
        version: "7.15",
        binary_id: "zpaq",
        build: DISTRO,
        encode: Some(cmd(
            "bash",
            &[
                "-c",
                "cd \"$(dirname \"$1\")\" && zpaq add \"$2\" \"$(basename \"$1\")\" -method 2 -threads 1 >/dev/null",
                "_",
                "{input}",
                "{output}",
            ],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "zpaq",
            &["extract", "{input}", "-to", "{output}", "-force"],
            OutputMode::Dir,
        )),
    }
}

// ---------------------------------------------------------------------------
// Case constructors
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn codec(
    id: &'static str,
    label: &'static str,
    format: &'static str,
    cli_format: Option<&'static str>,
    level: Option<u8>,
    backend: Option<&'static str>,
    size: SizeClass,
    reference: Option<RefSpec>,
    note: Option<&'static str>,
) -> Case {
    Case {
        id,
        label,
        kind: Kind::Codec,
        format,
        cli_format,
        ours_lib: true,
        ours_cli: cli_format.is_some(),
        encode: true,
        decode: true,
        level,
        backend,
        reference,
        note,
        size,
    }
}

fn codec_ours_only(
    id: &'static str,
    label: &'static str,
    format: &'static str,
    size: SizeClass,
    note: &'static str,
) -> Case {
    codec(
        id,
        label,
        format,
        Some(format),
        None,
        None,
        size,
        None,
        Some(note),
    )
}

fn codec_unavailable(id: &'static str, label: &'static str, note: &'static str) -> Case {
    Case {
        id,
        label,
        kind: Kind::Codec,
        format: "",
        cli_format: None,
        ours_lib: false,
        ours_cli: false,
        encode: false,
        decode: false,
        level: None,
        backend: None,
        reference: None,
        note: Some(note),
        size: TINY,
    }
}

fn archive(
    id: &'static str,
    label: &'static str,
    format: &'static str,
    encode: bool,
    reference: Option<RefSpec>,
    note: Option<&'static str>,
) -> Case {
    Case {
        id,
        label,
        kind: Kind::Archive,
        format,
        cli_format: Some(format),
        ours_lib: true,
        ours_cli: true,
        encode,
        decode: true,
        level: None,
        backend: None,
        reference,
        note,
        size: MEDIUM,
    }
}

fn archive_unsupported(id: &'static str, label: &'static str, note: &'static str) -> Case {
    Case {
        id,
        label,
        kind: Kind::Archive,
        format: "",
        cli_format: None,
        ours_lib: false,
        ours_cli: false,
        encode: false,
        decode: false,
        level: None,
        backend: None,
        reference: None,
        note: Some(note),
        size: MEDIUM,
    }
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

pub fn cases() -> Vec<Case> {
    vec![
        // Major codecs with system references.
        codec(
            "gzip",
            "gzip",
            "gzip",
            Some("gzip"),
            None,
            None,
            MEDIUM,
            Some(gzip_ref()),
            None,
        ),
        codec(
            "zlib",
            "zlib",
            "zlib",
            Some("zlib"),
            None,
            None,
            MEDIUM,
            Some(zlib_ref("zlib")),
            Some("Python reference startup is included; use the full size for stable numbers"),
        ),
        codec(
            "deflate",
            "raw DEFLATE",
            "deflate",
            Some("deflate"),
            None,
            None,
            MEDIUM,
            Some(zlib_ref("deflate")),
            Some("Python reference startup is included; use the full size for stable numbers"),
        ),
        codec(
            "zstd",
            "zstd",
            "zstd",
            Some("zstd"),
            None,
            None,
            MEDIUM,
            Some(zstd_ref()),
            None,
        ),
        codec_ours_only(
            "zstd-seekable",
            "zstd seekable",
            "zstd-seekable",
            MEDIUM,
            "No standalone seekable-format CLI in the baseline image",
        ),
        codec(
            "bzip2",
            "bzip2",
            "bzip2",
            Some("bzip2"),
            None,
            None,
            SLOW,
            Some(bzip2_ref()),
            None,
        ),
        codec(
            "lzip",
            "lzip",
            "lzip",
            Some("lzip"),
            None,
            None,
            SLOW,
            Some(lzip_ref()),
            None,
        ),
        codec(
            "lzma",
            "LZMA-Alone",
            "lzma",
            Some("lzma"),
            None,
            None,
            SLOW,
            Some(lzma_ref()),
            None,
        ),
        codec(
            "xz",
            "xz",
            "xz",
            Some("xz"),
            None,
            None,
            SLOW,
            Some(xz_ref()),
            None,
        ),
        codec(
            "lzw",
            "LZW (.Z)",
            "lzw",
            Some("lzw"),
            None,
            None,
            FAST,
            Some(lzw_ref()),
            None,
        ),
        codec(
            "lz4",
            "LZ4",
            "lz4",
            Some("lz4"),
            None,
            None,
            FAST,
            Some(lz4_ref()),
            None,
        ),
        codec(
            "lzo",
            "LZO (lzop)",
            "lzo",
            Some("lzo"),
            None,
            None,
            FAST,
            Some(lzo_ref()),
            None,
        ),
        codec(
            "brotli",
            "Brotli",
            "brotli",
            Some("brotli"),
            None,
            None,
            SLOW,
            Some(brotli_ref()),
            Some("Reference uses -q 5; our encoder has no public quality knob"),
        ),
        codec(
            "zpaq",
            "ZPAQ (raw stream)",
            "zpaq",
            None,
            Some(1),
            None,
            SLOW,
            None,
            Some("Reference zpaq CLI writes journaling archives; raw-stream comparison is N/A"),
        ),
        codec(
            "lrzip",
            "lrzip",
            "lrzip",
            Some("lrzip"),
            None,
            Some("lzma"),
            SLOW,
            Some(lrzip_ref()),
            None,
        ),
        codec(
            "rzip",
            "rzip",
            "rzip",
            Some("rzip"),
            None,
            None,
            SLOW,
            Some(rzip_ref()),
            None,
        ),
        // Codecs without a packaged reference in the baseline image.
        codec_ours_only(
            "snappy",
            "Snappy",
            "snappy",
            FAST,
            "No packaged reference CLI",
        ),
        codec_ours_only("lzf", "LZF", "lzf", FAST, "Reference CLI not packaged"),
        codec_ours_only(
            "fastlz",
            "FastLZ",
            "fastlz",
            FAST,
            "Reference CLI not packaged",
        ),
        codec_ours_only("lzrw1", "LZRW1", "lzrw1", FAST, "No packaged reference CLI"),
        codec_ours_only(
            "lzrw1a",
            "LZRW1-A",
            "lzrw1a",
            FAST,
            "No packaged reference CLI",
        ),
        codec_ours_only("lzrw2", "LZRW2", "lzrw2", FAST, "No packaged reference CLI"),
        codec_ours_only("lzrw3", "LZRW3", "lzrw3", FAST, "No packaged reference CLI"),
        codec_ours_only(
            "lzrw3a",
            "LZRW3-A",
            "lzrw3a",
            FAST,
            "No packaged reference CLI",
        ),
        codec_ours_only(
            "lzsa",
            "LZSA v1",
            "lzsa",
            FAST,
            "Reference CLI not built in baseline image",
        ),
        codec_ours_only(
            "lzsa2",
            "LZSA v2",
            "lzsa2",
            FAST,
            "Reference CLI not built in baseline image",
        ),
        codec_ours_only(
            "zx0",
            "ZX0",
            "zx0",
            FAST,
            "Reference CLI not built in baseline image",
        ),
        codec_ours_only(
            "zx1",
            "ZX1",
            "zx1",
            FAST,
            "Reference CLI not built in baseline image",
        ),
        codec_ours_only(
            "zx2",
            "ZX2",
            "zx2",
            FAST,
            "Reference CLI not built in baseline image",
        ),
        codec_ours_only(
            "zx5",
            "ZX5",
            "zx5",
            FAST,
            "Reference CLI not built in baseline image",
        ),
        codec_ours_only(
            "zx0b",
            "ZX0 backwards",
            "zx0b",
            FAST,
            "No standalone backwards reference CLI",
        ),
        codec_ours_only(
            "zx1b",
            "ZX1 backwards",
            "zx1b",
            FAST,
            "No standalone backwards reference CLI",
        ),
        codec_ours_only(
            "zx2b",
            "ZX2 backwards",
            "zx2b",
            FAST,
            "No standalone backwards reference CLI",
        ),
        codec_ours_only(
            "zx5b",
            "ZX5 backwards",
            "zx5b",
            FAST,
            "No standalone backwards reference CLI",
        ),
        codec_ours_only(
            "vcdiff",
            "VCDIFF",
            "vcdiff",
            MEDIUM,
            "xdelta3 not installed in baseline image",
        ),
        codec_ours_only(
            "mppc",
            "MPPC",
            "mppc",
            MEDIUM,
            "No packaged MPPC reference CLI",
        ),
        codec_ours_only(
            "lzs",
            "Stac LZS",
            "lzs",
            MEDIUM,
            "No packaged LZS reference CLI",
        ),
        codec_ours_only(
            "lzxd",
            "LZXD",
            "lzxd",
            MEDIUM,
            "cabextract decodes CAB, not a raw LZXD stream",
        ),
        codec_ours_only(
            "cmpsc",
            "CMPSC",
            "cmpsc",
            MEDIUM,
            "No Linux reference implementation",
        ),
        codec_ours_only(
            "xpress",
            "MS-XCA Xpress",
            "xpress",
            FAST,
            "No Linux reference implementation",
        ),
        codec_ours_only(
            "xpress-huff",
            "MS-XCA Xpress Huffman",
            "xpress-huff",
            FAST,
            "No Linux reference implementation",
        ),
        codec_ours_only(
            "lznt1",
            "MS-XCA LZNT1",
            "lznt1",
            FAST,
            "No Linux reference implementation",
        ),
        codec_unavailable(
            "packbits",
            "PackBits",
            "CLI/helper dispatch does not expose this transform",
        ),
        codec_unavailable(
            "yenc",
            "yEnc",
            "CLI/helper dispatch does not expose this transform",
        ),
        codec_unavailable(
            "macbinary",
            "MacBinary",
            "CLI/helper dispatch does not expose this transform",
        ),
        codec_unavailable(
            "uuencode",
            "uuencode",
            "CLI/helper dispatch does not expose this transform",
        ),
        codec_unavailable(
            "ascii85",
            "Ascii85",
            "CLI/helper dispatch does not expose this transform",
        ),
        codec_unavailable(
            "binhex",
            "BinHex",
            "CLI/helper dispatch does not expose this transform",
        ),
        // Archives with write support and a packaged reference.
        archive("tar", "tar", "tar", true, Some(tar_ref()), None),
        archive("cpio", "cpio (newc)", "cpio", true, Some(cpio_ref()), None),
        archive("ar", "ar", "ar", true, Some(ar_ref()), None),
        archive("zip", "zip", "zip", true, Some(zip_ref()), None),
        archive("7z", "7z", "7z", true, Some(sevenz_ref()), None),
        archive(
            "zpaq-archive",
            "ZPAQ archive",
            "zpaq",
            true,
            Some(zpaq_ref()),
            None,
        ),
        // Archives with our writer but no packaged reference encoder.
        archive(
            "lha",
            "LHA",
            "lha",
            true,
            None,
            Some("Lhasa is decode-only; no reference writer"),
        ),
        archive(
            "arj",
            "ARJ",
            "arj",
            true,
            None,
            Some("No packaged ARJ reference writer"),
        ),
        archive(
            "arc",
            "ARC",
            "arc",
            true,
            None,
            Some("No packaged ARC reference writer"),
        ),
        archive(
            "git-pack",
            "git pack",
            "git-pack",
            true,
            None,
            Some("git pack writer needs a repository oracle"),
        ),
        archive(
            "xar",
            "xar",
            "xar",
            true,
            None,
            Some("xar reference tool not installed"),
        ),
        // Read-only archive formats exposed by the CLI.
        archive(
            "deb",
            "deb",
            "deb",
            false,
            None,
            Some("read-only format; reference decode via ar+tar pending"),
        ),
        archive(
            "rpm",
            "rpm",
            "rpm",
            false,
            None,
            Some("read-only format; reference decode via rpm/bsdtar pending"),
        ),
        archive(
            "mscab",
            "CAB",
            "mscab",
            false,
            None,
            Some("reference decode via cabextract pending"),
        ),
        archive(
            "zim",
            "ZIM",
            "zim",
            false,
            None,
            Some("reference decode via zimtools pending"),
        ),
        archive(
            "mtree",
            "mtree",
            "mtree",
            false,
            None,
            Some("read-only metadata format"),
        ),
        archive(
            "warc",
            "WARC",
            "warc",
            false,
            None,
            Some("read-only format; no baseline reference"),
        ),
        archive_unsupported(
            "squashfs",
            "squashfs",
            "CLI read dispatch not implemented; library decode only",
        ),
        // Formats not exposed by the CLI read dispatch yet.
        archive_unsupported(
            "cramfs",
            "cramfs",
            "CLI read dispatch not implemented; library decode only",
        ),
        archive_unsupported(
            "romfs",
            "romfs",
            "CLI read dispatch not implemented; library decode only",
        ),
        archive_unsupported(
            "erofs",
            "erofs",
            "CLI read dispatch not implemented; library decode only",
        ),
        archive_unsupported(
            "iso9660",
            "ISO 9660",
            "CLI read dispatch not implemented; library decode only",
        ),
        archive_unsupported(
            "crx3",
            "CRX3",
            "CLI read dispatch not implemented; library decode only",
        ),
        archive_unsupported(
            "pea",
            "PEA",
            "CLI read dispatch not implemented; library decode only",
        ),
        archive_unsupported(
            "mscfb",
            "MS-CFB",
            "CLI read dispatch not implemented; library decode only",
        ),
    ]
}
