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
| deflate | raw DEFLATE | codec | measured | CPython zlib | system Python 3 / zlib | CPython zlib module; zlib C library built by the distribution | Python reference startup is included; our Default uses max_chain=32, so zlib level 6 is not parameter-identical |
| zstd | zstd | codec | measured | zstd | 1.5.7 | distro package (exact distro build flags not exposed) |  |
| zstd-seekable | zstd seekable | codec | ours-only | — | — | — | No standalone seekable-format CLI in the baseline image |
| bzip2 | bzip2 | codec | measured | bzip2 | 1.0.8 | distro package (exact distro build flags not exposed) |  |
| lzip | lzip | codec | measured | GNU lzip | 1.26 | distro package (exact distro build flags not exposed) |  |
| lzma | LZMA-Alone | codec | measured | XZ Utils (lzma-alone) | 5.8.4 | distro package (exact distro build flags not exposed) |  |
| xz | xz | codec | measured | XZ Utils | 5.8.4 | distro package (exact distro build flags not exposed) |  |
| lzw | LZW (.Z) | codec | measured | ncompress | 5.0 | distro package (exact distro build flags not exposed) |  |
| lz4 | LZ4 | codec | measured | lz4 | 1.10.0 | distro package (exact distro build flags not exposed) |  |
| lzo | LZO (lzop) | codec | measured | lzop | 1.04 | distro package (exact distro build flags not exposed) |  |
| brotli | Brotli | codec | measured | brotli | 1.2.0 | distro package (exact distro build flags not exposed) | Reference uses -q 5; our encoder has no public quality knob |
| zpaq | ZPAQ (raw stream) | codec | ours-only | — | — | — | Reference zpaq CLI writes journaling archives; raw-stream comparison is N/A |
| lrzip | lrzip | codec | measured | lrzip | 0.660 | distro package (exact distro build flags not exposed) | Our LZMA dictionary is 4 KiB; lrzip -L 7 uses a larger dictionary, so this is a speed/ratio comparison only |
| rzip | rzip | codec | measured | rzip | 2.1 | distro package (exact distro build flags not exposed) |  |
| snappy | Snappy | codec | ours-only | — | — | — | No packaged reference CLI |
| lzf | LZF | codec | measured | liblzf | 3.6 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 | Cross-validated against liblzf 3.6 |
| fastlz | FastLZ | codec | measured | FastLZ | 0.5.0 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 | Cross-validated against FastLZ 0.5.0 |
| lzrw1 | LZRW1 | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw1a | LZRW1-A | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw2 | LZRW2 | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw3 | LZRW3 | codec | ours-only | — | — | — | No packaged reference CLI |
| lzrw3a | LZRW3-A | codec | ours-only | — | — | — | No packaged reference CLI |
| lzsa | LZSA v1 | codec | measured | lzsa | 1.4.1 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 -Isrc/libdivsufsort/include -Isrc | LZSA v1 reference CLI from upstream source build |
| lzsa2 | LZSA v2 | codec | measured | lzsa | 1.4.1 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 -Isrc/libdivsufsort/include -Isrc | LZSA v2 reference CLI from upstream source build |
| zx0 | ZX0 | codec | measured | ZX0 | 2.2 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx0.c optimize.c compress.c memory.c) | ZX0 reference CLI from upstream source build |
| zx1 | ZX1 | codec | measured | ZX1 | 1.5 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx1.c optimize.c compress.c memory.c) | ZX1 reference CLI from upstream source build |
| zx2 | ZX2 | codec | measured | ZX2 | 1.1 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx2.c optimize.c compress.c memory.c) | ZX2 reference CLI from upstream source build |
| zx5 | ZX5 | codec | measured | ZX5 | 2.0 | source build: gcc -O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0 (zx5.c optimize.c compress.c memory.c) | ZX5 reference CLI from upstream source build |
| zx0b | ZX0 backwards | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| zx1b | ZX1 backwards | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| zx2b | ZX2 backwards | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| zx5b | ZX5 backwards | codec | ours-only | — | — | — | No standalone backwards reference CLI |
| vcdiff | VCDIFF | codec | ours-only | — | — | — | xdelta3 not installed in baseline image |
| mppc | MPPC | codec | ours-only | — | — | — | No packaged MPPC reference CLI; 8 KiB single-packet limit |
| lzs | Stac LZS | codec | ours-only | — | — | — | No packaged LZS reference CLI |
| lzxd | LZXD | codec | ours-only | — | — | — | cabextract decodes CAB, not a raw LZXD stream |
| cmpsc | CMPSC | codec | ours-only | — | — | — | No Linux reference implementation |
| xpress | MS-XCA Xpress | codec | ours-only | — | — | — | No Linux reference implementation; 32 KiB single-block benchmark size |
| xpress-huff | MS-XCA Xpress Huffman | codec | ours-only | — | — | — | No Linux reference implementation; 32 KiB single-block benchmark size |
| lznt1 | MS-XCA LZNT1 | codec | ours-only | — | — | — | No Linux reference implementation; 32 KiB single-block benchmark size |
| packbits | PackBits | codec | ours-only | — | — | — | Measured through the raw library helper; no packaged reference CLI |
| yenc | yEnc | codec | ours-only | — | — | — | Measured through the raw library helper; no external reference |
| macbinary | MacBinary | codec | ours-only | — | — | — | Measured through the raw library helper; no external reference |
| uuencode | uuencode | codec | measured | CPython binascii (uuencode) | system Python 3 | CPython stdlib binascii; distribution Python build | Measured through the raw library helper; CPython is the reference |
| ascii85 | Ascii85 | codec | measured | CPython base64 (Ascii85) | system Python 3 | CPython stdlib base64; distribution Python build | Measured through the raw library helper; CPython is the reference |
| binhex | BinHex | codec | ours-only | — | — | — | Measured through the raw library helper; no stable external reference |
| tar | tar | archive | measured | GNU tar | system tar | distro package (exact distro build flags not exposed) |  |
| cpio | cpio (newc) | archive | measured | GNU cpio | system cpio | distro package (exact distro build flags not exposed) |  |
| ar | ar | archive | measured | GNU ar | system binutils | distro package (exact distro build flags not exposed) |  |
| zip | zip | archive | measured | Info-ZIP zip | 3.0 | distro package (exact distro build flags not exposed) |  |
| 7z | 7z | archive | measured | 7-Zip | 26.04 | distro package (exact distro build flags not exposed) |  |
| zpaq-archive | ZPAQ archive | archive | measured | zpaq | 7.15 | distro package (exact distro build flags not exposed) |  |
| lha | LHA | archive | ours-only | — | — | — | Lhasa is decode-only; no reference writer |
| arj | ARJ | archive | ours-only | — | — | — | No packaged ARJ reference writer |
| arc | ARC | archive | unavailable | — | — | — | ARC writer requires 8.3 names; benchmark tree not adapted |
| git-pack | git pack | archive | ours-only | — | — | — | git pack stores object IDs; tree manifest verification is skipped |
| xar | xar | archive | ours-only | — | — | — | Checked-in xar fixture; decode-only (our writer/reader roundtrip is not bit-stable) |
| mscab | CAB | archive | ours-only | — | — | — | Checked-in CAB fixture; decode-only |
| deb | deb | archive | unavailable | — | — | — | decode benchmark needs a deb fixture; pending |
| rpm | rpm | archive | unavailable | — | — | — | decode benchmark needs an rpm fixture; pending |
| zim | ZIM | archive | unavailable | — | — | — | decode benchmark needs a ZIM fixture; pending |
| mtree | mtree | archive | unavailable | — | — | — | decode benchmark needs an mtree fixture; pending |
| warc | WARC | archive | unavailable | — | — | — | decode benchmark needs a WARC fixture; pending |
| squashfs | squashfs | archive | unavailable | — | — | — | CLI read dispatch not implemented; library decode only |
| cramfs | cramfs | archive | unavailable | — | — | — | CLI read dispatch not implemented; library decode only |
| romfs | romfs | archive | ours-only | — | — | — | Checked-in fixture; raw library decode only |
| erofs | erofs | archive | ours-only | — | — | — | Checked-in fixture; raw library decode only |
| iso9660 | ISO 9660 | archive | ours-only | — | — | — | Checked-in fixture; raw library decode only |
| crx3 | CRX3 | archive | unavailable | — | — | — | CLI read dispatch not implemented; library decode only |
| pea | PEA | archive | unavailable | — | — | — | CLI read dispatch not implemented; library decode only |
| mscfb | MS-CFB | archive | unavailable | — | — | — | CLI read dispatch not implemented; library decode only |
