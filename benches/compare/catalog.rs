//! Benchmark case catalog.
//!
//! Every user-facing format in `docs/spec/` is represented here. Formats
//! without a usable reference are still listed and measured on our side
//! when the CLI/helper dispatch supports them; the report marks the
//! reference column as N/A with the reason from `note`.

use crate::model::{
    Case, FAST, Kind, MEDIUM, OutputMode, PACKET, RefCommand, RefSpec, SLOW, SMALL, SizeClass,
    TINY, XCA, ZX,
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
    result = bytearray(b'begin 644 file\n')
    for i in range(0, len(data), 45):
        result += binascii.b2a_uu(data[i:i+45])
    result += b'`\nend\n'
else:
    result = bytearray()
    for line in data.splitlines():
        if line.startswith(b'begin ') or line == b'end':
            continue
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
if mode == 'encode':
    result = base64.a85encode(data, adobe=True)
else:
    result = base64.a85decode(data, adobe=data.startswith(b'<~'))
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
            &["-6", "-k", "-o", "{output}", "{input}"],
            OutputMode::None,
        )),
        decode: Some(cmd(
            "rzip",
            &["-d", "-k", "-o", "{output}", "{input}"],
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

fn lzf_ref() -> RefSpec {
    RefSpec {
        name: "liblzf",
        version: "3.6",
        binary_id: "lzf_ref",
        build: "source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0",
        encode: Some(cmd(
            "lzf_ref",
            &["encode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd(
            "lzf_ref",
            &["decode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
    }
}

fn fastlz_ref() -> RefSpec {
    RefSpec {
        name: "FastLZ",
        version: "0.5.0",
        binary_id: "fastlz_ref",
        build: "source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0",
        encode: Some(cmd(
            "fastlz_ref",
            &["encode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd(
            "fastlz_ref",
            &["decode", "{input}", "{output}"],
            OutputMode::Arg,
        )),
    }
}

fn lzsa_ref(format: u8) -> RefSpec {
    let encode_args: &'static [&'static str] = if format == 1 {
        &["-f", "1", "--prefer-speed", "{input}", "{output}"]
    } else {
        &["-f", "2", "--prefer-speed", "{input}", "{output}"]
    };
    RefSpec {
        name: "lzsa",
        version: "1.4.1",
        binary_id: "lzsa",
        build: "source build: gcc -O2 -fomit-frame-pointer -Isrc/libdivsufsort/include -Isrc",
        encode: Some(cmd("lzsa", encode_args, OutputMode::Arg)),
        decode: Some(cmd("lzsa", &["-d", "{input}", "{output}"], OutputMode::Arg)),
    }
}

fn zx0_ref() -> RefSpec {
    RefSpec {
        name: "ZX0",
        version: "2.2",
        binary_id: "zx0",
        build: "source build: gcc -O2 (zx0.c optimize.c compress.c memory.c)",
        encode: Some(cmd(
            "zx0",
            &["-q", "-f", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd("dzx0", &["{input}", "{output}"], OutputMode::Arg)),
    }
}

fn zx1_ref() -> RefSpec {
    RefSpec {
        name: "ZX1",
        version: "1.5",
        binary_id: "zx1",
        build: "source build: gcc -O2 (zx1.c optimize.c compress.c memory.c)",
        encode: Some(cmd(
            "zx1",
            &["-q", "-f", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd("dzx1", &["{input}", "{output}"], OutputMode::Arg)),
    }
}

fn zx2_ref() -> RefSpec {
    RefSpec {
        name: "ZX2",
        version: "1.1",
        binary_id: "zx2",
        build: "source build: gcc -O2 (zx2.c optimize.c compress.c memory.c)",
        encode: Some(cmd("zx2", &["-f", "{input}", "{output}"], OutputMode::Arg)),
        decode: Some(cmd("dzx2", &["{input}", "{output}"], OutputMode::Arg)),
    }
}

fn zx5_ref() -> RefSpec {
    RefSpec {
        name: "ZX5",
        version: "2.0",
        binary_id: "zx5",
        build: "source build: gcc -O2 (zx5.c optimize.c compress.c memory.c)",
        encode: Some(cmd(
            "zx5",
            &["-q", "-f", "{input}", "{output}"],
            OutputMode::Arg,
        )),
        decode: Some(cmd("dzx5", &["{input}", "{output}"], OutputMode::Arg)),
    }
}

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
                "cd \"$(dirname \"$1\")\" && find \"$(basename \"$1\")\" -type f -print0 | xargs -0 7z a -t7z -m0=lzma2:d=8m -mx=5 -mmt=1 -bso0 -bsp0 \"$2\"",
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
                "cd \"$(dirname \"$1\")\" && files=(); while IFS= read -r -d '' f; do files+=(\"$f\"); done < <(find \"$(basename \"$1\")\" -type f -print0); zpaq add \"$2\" \"${files[@]}\" -method 2 -threads 1 >/dev/null",
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
        raw: false,
        encode: true,
        decode: true,
        level,
        backend,
        reference,
        fixture: None,
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

fn codec_raw(
    id: &'static str,
    label: &'static str,
    format: &'static str,
    size: SizeClass,
    note: &'static str,
) -> Case {
    Case {
        id,
        label,
        kind: Kind::Codec,
        format,
        cli_format: None,
        ours_lib: true,
        ours_cli: false,
        raw: true,
        encode: true,
        decode: true,
        level: None,
        backend: None,
        reference: None,
        fixture: None,
        note: Some(note),
        size,
    }
}

fn codec_raw_with_ref(
    id: &'static str,
    label: &'static str,
    format: &'static str,
    size: SizeClass,
    reference: RefSpec,
    note: &'static str,
) -> Case {
    Case {
        id,
        label,
        kind: Kind::Codec,
        format,
        cli_format: None,
        ours_lib: true,
        ours_cli: false,
        raw: true,
        encode: true,
        decode: true,
        level: None,
        backend: None,
        reference: Some(reference),
        fixture: None,
        note: Some(note),
        size,
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
        raw: false,
        encode,
        decode: true,
        level: None,
        backend: None,
        reference,
        fixture: None,
        note,
        size: MEDIUM,
    }
}

fn archive_fixture(
    id: &'static str,
    label: &'static str,
    format: &'static str,
    fixture: &'static str,
    note: &'static str,
) -> Case {
    Case {
        id,
        label,
        kind: Kind::Archive,
        format,
        cli_format: Some(format),
        ours_lib: true,
        ours_cli: true,
        raw: false,
        encode: false,
        decode: true,
        level: None,
        backend: None,
        reference: None,
        fixture: Some(fixture),
        note: Some(note),
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
        raw: false,
        encode: false,
        decode: false,
        level: None,
        backend: None,
        reference: None,
        fixture: None,
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
        codec(
            "lzf",
            "LZF",
            "lzf",
            Some("lzf"),
            None,
            None,
            FAST,
            Some(lzf_ref()),
            Some("Cross-validated against liblzf 3.6"),
        ),
        codec(
            "fastlz",
            "FastLZ",
            "fastlz",
            Some("fastlz"),
            None,
            None,
            FAST,
            Some(fastlz_ref()),
            Some("Cross-validated against FastLZ 0.5.0"),
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
        codec(
            "lzsa",
            "LZSA v1",
            "lzsa",
            Some("lzsa"),
            None,
            None,
            SMALL,
            Some(lzsa_ref(1)),
            Some("LZSA v1 reference CLI from upstream source build"),
        ),
        codec(
            "lzsa2",
            "LZSA v2",
            "lzsa2",
            Some("lzsa2"),
            None,
            None,
            SMALL,
            Some(lzsa_ref(2)),
            Some("LZSA v2 reference CLI from upstream source build"),
        ),
        codec(
            "zx0",
            "ZX0",
            "zx0",
            Some("zx0"),
            None,
            None,
            ZX,
            Some(zx0_ref()),
            Some("ZX0 reference CLI from upstream source build"),
        ),
        codec(
            "zx1",
            "ZX1",
            "zx1",
            Some("zx1"),
            None,
            None,
            ZX,
            Some(zx1_ref()),
            Some("ZX1 reference CLI from upstream source build"),
        ),
        codec(
            "zx2",
            "ZX2",
            "zx2",
            Some("zx2"),
            None,
            None,
            ZX,
            Some(zx2_ref()),
            Some("ZX2 reference CLI from upstream source build"),
        ),
        codec(
            "zx5",
            "ZX5",
            "zx5",
            Some("zx5"),
            None,
            None,
            ZX,
            Some(zx5_ref()),
            Some("ZX5 reference CLI from upstream source build"),
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
            PACKET,
            "No packaged MPPC reference CLI; 8 KiB single-packet limit",
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
            XCA,
            "No Linux reference implementation; 32 KiB single-block benchmark size",
        ),
        codec_ours_only(
            "xpress-huff",
            "MS-XCA Xpress Huffman",
            "xpress-huff",
            XCA,
            "No Linux reference implementation; 32 KiB single-block benchmark size",
        ),
        codec_ours_only(
            "lznt1",
            "MS-XCA LZNT1",
            "lznt1",
            XCA,
            "No Linux reference implementation; 32 KiB single-block benchmark size",
        ),
        codec_raw(
            "packbits",
            "PackBits",
            "packbits",
            FAST,
            "Measured through the raw library helper; no packaged reference CLI",
        ),
        codec_raw(
            "yenc",
            "yEnc",
            "yenc",
            FAST,
            "Measured through the raw library helper; no external reference",
        ),
        codec_raw(
            "macbinary",
            "MacBinary",
            "macbinary",
            TINY,
            "Measured through the raw library helper; no external reference",
        ),
        codec_raw_with_ref(
            "uuencode",
            "uuencode",
            "uuencode",
            FAST,
            uuencode_ref(),
            "Measured through the raw library helper; CPython is the reference",
        ),
        codec_raw_with_ref(
            "ascii85",
            "Ascii85",
            "ascii85",
            FAST,
            ascii85_ref(),
            "Measured through the raw library helper; CPython is the reference",
        ),
        codec_raw(
            "binhex",
            "BinHex",
            "binhex",
            TINY,
            "Measured through the raw library helper; no stable external reference",
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
        archive_unsupported(
            "arc",
            "ARC",
            "ARC writer requires 8.3 names; benchmark tree not adapted",
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
        archive_fixture(
            "mscab",
            "CAB",
            "mscab",
            "tests/fixtures/mscab/lzx_mixed.cab",
            "Checked-in CAB fixture; decode-only",
        ),
        archive_unsupported(
            "deb",
            "deb",
            "decode benchmark needs a deb fixture; pending",
        ),
        archive_unsupported(
            "rpm",
            "rpm",
            "decode benchmark needs an rpm fixture; pending",
        ),
        archive_unsupported(
            "zim",
            "ZIM",
            "decode benchmark needs a ZIM fixture; pending",
        ),
        archive_unsupported(
            "mtree",
            "mtree",
            "decode benchmark needs an mtree fixture; pending",
        ),
        archive_unsupported(
            "warc",
            "WARC",
            "decode benchmark needs a WARC fixture; pending",
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
