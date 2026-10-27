#!/usr/bin/env python3
"""Build pinned source reference implementations for the benchmark harness.

The harness prefers `target/bench/refs/bin/<tool>` over PATH, so these
builds do not replace or shadow distro packages. Every build records the
compiler, optimization flags, source revision, and binary sha256 in
`target/bench/refs/build-info.json`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "target" / "bench" / "refs"
SRC = TARGET / "src"
BIN = TARGET / "bin"
BUILD_INFO = TARGET / "build-info.json"

CFLAGS = ["-O2", "-march=x86-64", "-mtune=generic", "-fomit-frame-pointer", "-g0"]
CFLAGS_TEXT = " ".join(CFLAGS)
LDFLAGS = ""

REFS = {
    "zx0": {
        "url": "https://github.com/einar-saukas/ZX0.git",
        "commit": "ecde3a2ae05061fe06469ed46df81a33b7de7d86",
        "version": "2.2",
        "license": "BSD-3-Clause",
        "compress": ["zx0.c", "optimize.c", "compress.c", "memory.c"],
        "decompress": ["dzx0.c"],
    },
    "zx1": {
        "url": "https://github.com/einar-saukas/ZX1.git",
        "commit": "11e31cf91047562bb3cdedab1b34bb02ebdc8f83",
        "version": "1.5",
        "license": "BSD-3-Clause",
        "compress": ["zx1.c", "optimize.c", "compress.c", "memory.c"],
        "decompress": ["dzx1.c"],
    },
    "zx2": {
        "url": "https://github.com/einar-saukas/ZX2.git",
        "commit": "dc963faad50dfebd8b38e6bef4f027ff4754419d",
        "version": "1.1",
        "license": "BSD-3-Clause",
        "compress": ["zx2.c", "optimize.c", "compress.c", "memory.c"],
        "decompress": ["dzx2.c"],
    },
    "zx5": {
        "url": "https://github.com/einar-saukas/ZX5.git",
        "commit": "61616ffd641fb15add702663f57e3b3067d25ee5",
        "version": "2.0",
        "license": "BSD-3-Clause",
        "compress": ["zx5.c", "optimize.c", "compress.c", "memory.c"],
        "decompress": ["dzx5.c"],
    },
    "lzf": {
        "url": "https://dist.schmorp.de/liblzf/liblzf-3.6.tar.gz",
        "sha256": "9c5de01f7b9ccae40c3f619d26a7abec9986c06c36d260c179cedd04b89fb46a",
        "dir": "liblzf-3.6",
        "version": "3.6",
        "license": "BSD-2-Clause OR GPL-2.0-or-later",
        "sources": ["lzf_c.c", "lzf_d.c"],
        "driver": "lzf_driver.c",
        "binary": "lzf_ref",
    },
    "fastlz": {
        "url": "https://github.com/ariya/FastLZ/archive/refs/tags/0.5.0.tar.gz",
        "sha256": "4bd422e06ff53e95b743818096a17bfda47f73ce14f14c7d3d74b91dd139d580",
        "dir": "FastLZ-0.5.0",
        "version": "0.5.0",
        "license": "MIT",
        "sources": ["fastlz.c"],
        "driver": "fastlz_driver.c",
        "binary": "fastlz_ref",
    },
    "snappy": {
        "url": "https://github.com/google/snappy/archive/refs/tags/1.2.1.tar.gz",
        "sha256": "736aeb64d86566d2236ddffa2865ee5d7a82d26c9016b36218fcc27ea4f09f86",
        "dir": "snappy-1.2.1",
        "version": "1.2.1",
        "license": "BSD-3-Clause",
        "sources": ["snappy.cc", "snappy-sinksource.cc", "snappy-stubs-internal.cc"],
        "driver": "snappy_driver.cc",
        "binary": "snappy_ref",
        "compiler": "g++",
        "stubs": "snappy-stubs-public.h",
    },
    "lzrw1": {
        "url": "https://ftp.funet.fi/pub/misc/compression/lzrw1.c",
        "sha256": "15f3654238d8669e349c3442e9c13e18bfac04ee7bccc17a2bdf9f899750a731",
        "filename": "lzrw1.c",
        "version": "LZRW1 (1991)",
        "license": "public domain",
        "driver": "lzrw_driver.c",
        "binary": "lzrw1_ref",
        "include_driver": ["lzrw"],
        "defines": ["USE_LZRW1"],
        "cflags_extra": ["-std=gnu89"],
        "comment_preamble": "#define UBYTE",
    },
    "lzrw1a": {
        "url": "https://ftp.funet.fi/pub/misc/compression/lzrw1-a.c",
        "sha256": "ff91f657b4928037b70749948d7eab223c79f3c27f801f299af739522cb006f3",
        "filename": "lzrw1-a.c",
        "version": "LZRW1-A (1991)",
        "license": "public domain",
        "driver": "lzrw_driver.c",
        "binary": "lzrw1a_ref",
        "include_driver": ["lzrw"],
        "defines": ["USE_LZRW1A"],
        "cflags_extra": ["-std=gnu89"],
        "comment_preamble": '#include "port.h"',
        "patch_hash_align": True,
    },
    "lzrw2": {
        "url": "https://ftp.funet.fi/pub/misc/compression/lzrw2.c",
        "sha256": "69796dde5ffc38d60180c607eb848348d8bd00062062d9beb76dbc448993a31c",
        "filename": "lzrw2.c",
        "version": "LZRW2 (1991)",
        "license": "public domain",
        "driver": "lzrw_driver.c",
        "binary": "lzrw2_ref",
        "include_driver": ["lzrw"],
        "defines": ["USE_LZRW2"],
        "cflags_extra": ["-std=gnu89"],
    },
    "lzrw3": {
        "url": "https://ftp.funet.fi/pub/misc/compression/lzrw3.c",
        "sha256": "e655dd72e1b2f4e0d1a3901007a922b88b4ed6bc2deebdc97dc13cf49d04d1db",
        "filename": "lzrw3.c",
        "version": "LZRW3 (1991)",
        "license": "public domain",
        "driver": "lzrw_driver.c",
        "binary": "lzrw3_ref",
        "include_driver": ["lzrw"],
        "defines": ["USE_LZRW3"],
        "cflags_extra": ["-std=gnu89"],
    },
    "lzrw3a": {
        "url": "https://ftp.funet.fi/pub/misc/compression/lzrw3-a.c",
        "sha256": "fef5eec83c37f891f9efd983c6c7ae35c1b609c116c8485a38223ec624713867",
        "filename": "lzrw3-a.c",
        "version": "LZRW3-A (1991)",
        "license": "public domain",
        "driver": "lzrw_driver.c",
        "binary": "lzrw3a_ref",
        "include_driver": ["lzrw"],
        "defines": ["USE_LZRW3A"],
        "cflags_extra": ["-std=gnu89"],
    },
    "lzs": {
        "url": "https://github.com/cmcqueen/lzs-compression/archive/10f122bf5214a5bbf5dd60d45bcae703967676af.tar.gz",
        "sha256": "002bf9a598f7293aa15877db424aeaa2b2a8d9585a92829e43b0f5604fa00ae2",
        "dir": "lzs-compression-10f122bf5214a5bbf5dd60d45bcae703967676af",
        "version": "lzs-compression (10f122bf)",
        "license": "MIT",
        "sources": ["c/src/liblzs/lzs-compression.c", "c/src/liblzs/lzs-decompression.c"],
        "driver": "lzs_driver.c",
        "binary": "lzs_ref",
        "include_root": ["c/src/liblzs"],
    },
    "lzsa": {
        "url": "https://github.com/emmanuel-marty/lzsa.git",
        "commit": "15ee2dfe118eeb8f7683ca44f64821c3a61ca1e5",
        "version": "1.4.1",
        "license": "zlib / CC0 (src/matchfinder.c)",
        "make": True,
    },
}


def run(command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=cwd, env=env, check=True)


def compiler_version(compiler: str = "gcc") -> str:
    output = subprocess.check_output([compiler, "--version"], text=True)
    return output.splitlines()[0]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def clone(name: str, spec: dict) -> Path:
    dest = SRC / name
    if dest.exists() and (dest / ".git").exists():
        head = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(dest), "status", "--porcelain"], text=True
        ).strip()
        if head == spec["commit"] and not dirty:
            return dest
        shutil.rmtree(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--quiet", spec["url"], str(dest)])
    run(["git", "-C", str(dest), "checkout", "--quiet", spec["commit"]])
    return dest


def fetch_archive(name: str, spec: dict) -> Path:
    dest = SRC / name
    if dest.exists():
        shutil.rmtree(dest)
    downloads = TARGET / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / f"{name}.tar.gz"
    if not archive.exists():
        print(f"downloading {spec['url']}")
        urllib.request.urlretrieve(spec["url"], archive)
    actual = sha256(archive)
    if actual != spec["sha256"]:
        raise SystemExit(f"{name}: sha256 mismatch: {actual}")
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(SRC, filter="data")
    extracted = SRC / spec["dir"]
    if not extracted.exists():
        raise SystemExit(f"{name}: extracted directory {extracted} not found")
    extracted.rename(dest)
    return dest


def fetch_file(name: str, spec: dict) -> Path:
    dest = SRC / name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    downloads = TARGET / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    filename = spec["filename"]
    cached = downloads / f"{name}-{filename}"
    if not cached.exists():
        print(f"downloading {spec['url']}")
        urllib.request.urlretrieve(spec["url"], cached)
    actual = sha256(cached)
    if actual != spec["sha256"]:
        raise SystemExit(f"{name}: sha256 mismatch: {actual}")
    shutil.copy2(cached, dest / filename)
    return dest


def prepare_lzrw_source(root: Path, spec: dict) -> None:
    if "comment_preamble" not in spec:
        return
    path = root / spec["filename"]
    text = path.read_text()
    marker = spec["comment_preamble"]
    index = text.index(marker)
    head, tail = text[:index], text[index:]
    lines = []
    in_block = False
    for line in head.splitlines():
        if in_block:
            lines.append(line)
            if "*/" in line:
                in_block = False
        elif line.strip().startswith("/*"):
            lines.append(line)
            if "*/" not in line:
                in_block = True
        elif not line.strip() or line.strip().startswith("*"):
            lines.append(line)
        else:
            lines.append("//" + line)
    path.write_text("\n".join(lines) + "\n" + tail)


def build_driver(name: str, spec: dict, root: Path) -> dict:
    commands = []
    patches = []
    if "comment_preamble" in spec:
        prepare_lzrw_source(root, spec)
        patches.append(
            {
                "file": str(root / spec["filename"]),
                "action": "comment_preamble",
                "marker": spec["comment_preamble"],
            }
        )
    if spec.get("patch_hash_align"):
        source = root / spec["filename"]
        old = "& 0xFFFFFFFC)"
        new = "& ~(ULONG)3)"
        text = source.read_text()
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"{name}: expected one hash-alignment site, found {count}")
        source.write_text(text.replace(old, new, 1))
        patches.append({"file": str(source), "from": old, "to": new})
    if "stubs" in spec:
        stub_script = Path(__file__).resolve().parent / "drivers" / "snappy_stubs.py"
        stub_command = [sys.executable, str(stub_script), str(root)]
        run(stub_command)
        commands.append(" ".join(stub_command))
    driver = Path(__file__).resolve().parent / "drivers" / spec["driver"]
    out = BIN / spec["binary"]
    command = [
        spec.get("compiler", "gcc"),
        *CFLAGS,
        *spec.get("cflags_extra", []),
        "-I",
        str(root),
        *[item for inc in spec.get("include_driver", []) for item in ("-I", str(driver.parent / inc))],
        *[item for inc in spec.get("include_root", []) for item in ("-I", str(root / inc))],
        *[f"-D{define}" for define in spec.get("defines", [])],
        "-o",
        str(out),
        str(driver),
        *[str(root / source) for source in spec.get("sources", [])],
    ]
    run(command)
    commands.append(" ".join(command))
    compiler = spec.get("compiler", "gcc")
    return {
        "id": name,
        "version": spec["version"],
        "source": spec["url"],
        "source_sha256": spec["sha256"],
        "license": spec["license"],
        "build": {
            "cc": compiler,
            "cc_version": compiler_version(compiler),
            "cflags": " ".join([*CFLAGS, *spec.get("cflags_extra", [])]),
            "ldflags": LDFLAGS,
            "commands": commands,
            **({"patches": patches} if patches else {}),
        },
        "binaries": [{"binary": str(out.relative_to(ROOT)), "sha256": sha256(out)}],
    }


def build_zx(name: str, spec: dict, root: Path) -> dict:
    src = root / "src"
    outputs = []
    commands = []
    for tool, files in (
        (name, spec["compress"]),
        (name.replace("zx", "dzx"), spec["decompress"]),
    ):
        out = BIN / tool
        command = [
            "gcc",
            *CFLAGS,
            "-I",
            str(src),
            "-o",
            str(out),
            *[str(src / file) for file in files],
        ]
        run(command)
        commands.append(" ".join(command))
        outputs.append({"binary": str(out.relative_to(ROOT)), "sha256": sha256(out)})
    return {
        "id": name,
        "version": spec["version"],
        "source": spec["url"],
        "commit": spec["commit"],
        "license": spec["license"],
        "build": {
            "cc": spec.get("compiler", "gcc"),
            "cc_version": compiler_version(),
            "cflags": CFLAGS_TEXT,
            "ldflags": LDFLAGS,
            "commands": commands,
        },
        "binaries": outputs,
    }


def build_lzsa(name: str, spec: dict, root: Path) -> dict:
    cflags = CFLAGS_TEXT + " -Isrc/libdivsufsort/include -Isrc"
    run(["make", "-C", str(root), "clean", "CC=gcc", f"CFLAGS={cflags}"])
    run(["make", "-C", str(root), "all", "CC=gcc", f"CFLAGS={cflags}"])
    out = BIN / name
    shutil.copy2(root / name, out)
    return {
        "id": name,
        "version": spec["version"],
        "source": spec["url"],
        "commit": spec["commit"],
        "license": spec["license"],
        "build": {
            "cc": spec.get("compiler", "gcc"),
            "cc_version": compiler_version(),
            "cflags": cflags,
            "ldflags": LDFLAGS,
            "commands": [
                f"make -C {root} clean CC=gcc CFLAGS={cflags}",
                f"make -C {root} all CC=gcc CFLAGS={cflags}",
            ],
        },
        "binaries": [{"binary": str(out.relative_to(ROOT)), "sha256": sha256(out)}],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("refs", nargs="*", help="reference ids (default: all)")
    parser.add_argument("--force", action="store_true", help="re-clone sources")
    args = parser.parse_args()

    BIN.mkdir(parents=True, exist_ok=True)
    SRC.mkdir(parents=True, exist_ok=True)
    selected = args.refs or list(REFS)
    unknown = sorted(set(selected) - set(REFS))
    if unknown:
        parser.error(f"unknown reference(s): {', '.join(unknown)}")

    existing = {}
    if BUILD_INFO.exists():
        try:
            for entry in json.loads(BUILD_INFO.read_text()).get("refs", []):
                existing[entry["id"]] = entry
        except (json.JSONDecodeError, KeyError):
            existing = {}
    info = {}
    for name in selected:
        spec = REFS[name]
        if args.force:
            shutil.rmtree(SRC / name, ignore_errors=True)
        if spec.get("filename"):
            root = fetch_file(name, spec)
        elif spec.get("sha256"):
            root = fetch_archive(name, spec)
        else:
            root = clone(name, spec)
        revision = spec.get("commit", spec.get("sha256", "unknown"))
        print(f"building {name} {spec['version']} ({revision[:12]})")
        if spec.get("make"):
            info[name] = build_lzsa(name, spec, root)
        elif spec.get("driver"):
            info[name] = build_driver(name, spec, root)
        else:
            info[name] = build_zx(name, spec, root)

    existing.update(info)
    BUILD_INFO.write_text(
        json.dumps({"refs": [existing[key] for key in sorted(existing)]}, indent=2) + "\n"
    )
    print(f"wrote {BUILD_INFO.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
