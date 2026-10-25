# Reference source builds

`build.py` fetches pinned upstream sources into `target/bench/refs/src/`
and builds them into `target/bench/refs/bin/`. The harness prefers these
binaries over PATH **inside the benchmark child process**; they are not
installed system-wide and do not replace distro packages.

```sh
make bench-refs
python3 docs/bench/refs/build.py zx0 lzsa --force
```

## Pinned revisions and flags

| id | version | source revision | license | build |
|---|---|---|---|---|
| `zx0` | 2.2 | `ecde3a2ae05061fe06469ed46df81a33b7de7d86` | BSD-3-Clause | `gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0` |
| `zx1` | 1.5 | `11e31cf91047562bb3cdedab1b34bb02ebdc8f83` | BSD-3-Clause | same |
| `zx2` | 1.1 | `dc963faad50dfebd8b38e6bef4f027ff4754419d` | BSD-3-Clause | same |
| `zx5` | 2.0 | `61616ffd641fb15add702663f57e3b3067d25ee5` | BSD-3-Clause | same |
| `lzsa` | 1.4.1 | `15ee2dfe118eeb8f7683ca44f64821c3a61ca1e5` | zlib / CC0 | `make CC=gcc CFLAGS='-O2 ... -Isrc/libdivsufsort/include -Isrc'` |
| `lzf` | 3.6 | sha256 `9c5de0...fb46a` | BSD-2-Clause OR GPL-2.0-or-later | `gcc -O2 ... drivers/lzf_driver.c lzf_c.c lzf_d.c` |
| `fastlz` | 0.5.0 | sha256 `4bd422...9d580` | MIT | `gcc -O2 ... drivers/fastlz_driver.c fastlz.c` |

The exact commands, compiler version, CFLAGS, and binary sha256 are written
to `target/bench/refs/build-info.json`. The report's Markdown table shows the
catalog flags and the binary `.comment`; `result.json` embeds the complete
`build-info.json` under `refs_build`.

The LZF and FastLZ drivers are benchmark-only adapters around the upstream
C APIs. They are not part of the `archive` crate and are not distributed as
libraries.

Sources fetched here are not committed. They are placed under `target/`,
which is ignored by git.
