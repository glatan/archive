# Benchmark reference matrix

Generated from the benchmark catalog. Regenerate with:

```sh
cargo bench --all-features --bench compare -- --list-markdown > docs/bench/reference-matrix.md
```

Status below is catalog-level. Runtime availability (for example a
missing reference binary) is recorded in the generated report.

| id | format | kind | status | reference | version | build flags / provenance | note |
|---|---|---|---|---|---|---|---|
| gzip | gzip | codec | measured | GNU gzip | 1.15 | distro package (exact distro build flags not exposed) | Our Default uses max_chain=32; gzip -6 is not parameter-identical |
| zlib | zlib | codec | measured | CPython zlib | system Python 3 / zlib | CPython zlib module; zlib C library built by the distribution | Python reference startup is included; our Default uses max_chain=32, so zlib level 6 is not parameter-identical |
| deflate | deflate | codec | measured | CPython zlib | system Python 3 / zlib | CPython zlib module; zlib C library built by the distribution | Python reference startup is included; our Default uses max_chain=32, so zlib level 6 is not parameter-identical |
| zstd | zstd | codec | measured | zstd | 1.5.7 | distro package (exact distro build flags not exposed) |  |
| zstd-seekable | zstd-seekable | codec | ours-only | — | — | — | No standalone seekable-format CLI in the baseline image |
| bzip2 | bzip2 | codec | measured | bzip2 | 1.0.8 | distro package (exact distro build flags not exposed) |  |
| lzip | lzip | codec | measured | GNU lzip | 1.26 | distro package (exact distro build flags not exposed) |  |
| lzma | lzma | codec | measured | XZ Utils (lzma-alone) | 5.8.4 | distro package (exact distro build flags not exposed) |  |
| xz | xz | codec | measured | XZ Utils | 5.8.4 | distro package (exact distro build flags not exposed) |  |
| lzw | lzw | codec | measured | ncompress | 5.0 | distro package (exact distro build flags not exposed) |  |
| lz4 | lz4 | codec | measured | lz4 | 1.10.0 | distro package (exact distro build flags not exposed) |  |
| lzo | lzo | codec | measured | lzop | 1.04 | distro package (exact distro build flags not exposed) |  |
| brotli | brotli | codec | measured | brotli | 1.2.0 | distro package (exact distro build flags not exposed) | Reference uses -q 5; our encoder has no public quality knob |
| zpaq | zpaq | codec | ours-only | — | — | — | Reference zpaq CLI writes journaling archives; raw-stream comparison is N/A |
| lrzip | lrzip | codec | measured | lrzip | 0.660 | distro package (exact distro build flags not exposed) | Our LZMA dictionary is 4 KiB; lrzip -L 7 uses a larger dictionary, so this is a speed/ratio comparison only |
| rzip | rzip | codec | measured | rzip | 2.1 | distro package (exact distro build flags not exposed) |  |
| snappy | snappy | codec | ours-only | — | — | — | No packaged reference CLI for the framed stream |
| snappy-raw | snappy | codec | measured | Snappy | 1.2.1 | source build: g++ -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 | Raw-block comparison against upstream Snappy |
| lzf | lzf | codec | measured | liblzf | 3.6 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 | Cross-validated against liblzf 3.6 |
| fastlz | fastlz | codec | measured | FastLZ | 0.5.0 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 | Cross-validated against FastLZ 0.5.0 |
| lzrw1 | lzrw1 | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw1a | lzrw1a | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw2 | lzrw2 | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw3 | lzrw3 | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw3a | lzrw3a | codec | ours-only | — | — | — | No packaged reference CLI |
| lzsa | lzsa | codec | measured | lzsa | 1.4.1 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 -Isrc/libdivsufsort/include -Isrc | LZSA v1 reference CLI from upstream source build |
| lzsa2 | lzsa2 | codec | measured | lzsa | 1.4.1 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 -Isrc/libdivsufsort/include -Isrc | LZSA v2 reference CLI from upstream source build |
| zx0 | zx0 | codec | measured | ZX0 | 2.2 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx0.c optimize.c compress.c memory.c) | ZX0 reference CLI from upstream source build |
| zx1 | zx1 | codec | measured | ZX1 | 1.5 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx1.c optimize.c compress.c memory.c) | ZX1 reference CLI from upstream source build |
| zx2 | zx2 | codec | measured | ZX2 | 1.1 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx2.c optimize.c compress.c memory.c) | ZX2 reference CLI from upstream source build |
| zx5 | zx5 | codec | measured | ZX5 | 2.0 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx5.c optimize.c compress.c memory.c) | ZX5 reference CLI from upstream source build |
| zx0b | zx0b | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| zx1b | zx1b | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| zx2b | zx2b | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| zx5b | zx5b | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| vcdiff | vcdiff | codec | ours-only | — | — | — | xdelta3 not installed in baseline image |
| mppc | mppc | codec | ours-only | — | — | — | No packaged MPPC reference CLI; 8 KiB single-packet limit |
| lzs | lzs | codec | ours-only | — | — | — | No packaged LZS reference CLI |
| lzxd | lzxd | codec | ours-only | — | — | — | cabextract decodes CAB, not a raw LZXD stream |
| cmpsc | cmpsc | codec | ours-only | — | — | — | No Linux reference implementation |
| xpress | xpress | codec | ours-only | — | — | — | No Linux reference implementation; 32 KiB single-block benchmark size |
| xpress-huff | xpress-huff | codec | ours-only | — | — | — | No Linux reference implementation; 32 KiB single-block benchmark size |
| lznt1 | lznt1 | codec | ours-only | — | — | — | No Linux reference implementation; 32 KiB single-block benchmark size |
| packbits | packbits | codec | ours-only | — | — | — | Measured through the raw library helper; no packaged reference CLI |
| yenc | yenc | codec | ours-only | — | — | — | Measured through the raw library helper; no external reference |
| macbinary | macbinary | codec | ours-only | — | — | — | Measured through the raw library helper; no external reference |
| uuencode | uuencode | codec | measured | CPython binascii (uuencode) | system Python 3 | CPython stdlib binascii; distribution Python build | Measured through the raw library helper; CPython is the reference |
| ascii85 | ascii85 | codec | measured | CPython base64 (Ascii85) | system Python 3 | CPython stdlib base64; distribution Python build | Measured through the raw library helper; CPython is the reference |
| binhex | binhex | codec | ours-only | — | — | — | Measured through the raw library helper; no stable external reference |
| tar | tar | archive | measured | GNU tar | system tar | distro package (exact distro build flags not exposed) |  |
| cpio | cpio | archive | measured | GNU cpio | system cpio | distro package (exact distro build flags not exposed) |  |
| ar | ar | archive | measured | GNU ar | system binutils | distro package (exact distro build flags not exposed) |  |
| zip | zip | archive | measured | Info-ZIP zip | 3.0 | distro package (exact distro build flags not exposed) |  |
| 7z | 7z | archive | measured | 7-Zip | 26.04 | distro package (exact distro build flags not exposed) |  |
| zpaq-archive | zpaq | archive | measured | zpaq | 7.15 | distro package (exact distro build flags not exposed) |  |
| lha | lha | archive | decode-only | lhasa | system lhasa | distro package (exact distro build flags not exposed) | Checked-in LHA fixture; decode reference is lhasa |
| arj | arj | archive | measured | unar | system unarchiver | distro package (exact distro build flags not exposed) | Decode reference is unar; no reference writer |
| arc | arc | archive | measured | unar | system unarchiver | distro package (exact distro build flags not exposed) | Uses a DOS 8.3 flat tree; decode reference is unar |
| git-pack | git-pack | archive | ours-only | — | — | — | git pack stores object IDs; payload hashes are compared instead of names |
| xar | xar | archive | measured | unar | system unarchiver | distro package (exact distro build flags not exposed) | Generated archive; decode reference is unar |
| mscab | mscab | archive | decode-only | cabextract | system cabextract | distro package (exact distro build flags not exposed) | Checked-in CAB fixture; decode reference is cabextract |
| deb | deb | archive | ours-only | — | — | — | Generated .deb fixture; decode-only |
| rpm | rpm | archive | decode-only | bsdtar | system libarchive | distro package (exact distro build flags not exposed) | Generated .rpm fixture; decode reference is bsdtar |
| zim | zim | archive | ours-only | — | — | — | Generated ZIM fixture; decode-only |
| mtree | mtree | archive | ours-only | — | — | — | Generated mtree fixture; metadata-only, CLI uses test |
| warc | warc | archive | ours-only | — | — | — | Generated WARC fixture; decode-only |
| squashfs | squashfs | archive | decode-only | unsquashfs | system squashfs-tools | distro package (exact distro build flags not exposed) | Generated squashfs fixture; decode reference is unsquashfs |
| cramfs | cramfs | archive | ours-only | — | — | — | Generated cramfs fixture; raw library decode only |
| romfs | romfs | archive | ours-only | — | — | — | Checked-in fixture; raw library decode only |
| erofs | erofs | archive | ours-only | — | — | — | Checked-in fixture; raw library decode only |
| iso9660 | iso9660 | archive | decode-only | bsdtar | system libarchive | distro package (exact distro build flags not exposed) | Checked-in fixture; decode reference is bsdtar |
| crx3 | crx3 | archive | ours-only | — | — | — | Generated CRX3 fixture; raw library decode only |
| pea | pea | archive | ours-only | — | — | — | Generated PEA fixture; raw library decode only |
| mscfb | mscfb | archive | ours-only | — | — | — | Generated MS-CFB fixture; raw library decode only |
