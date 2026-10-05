# Test fixtures

このディレクトリには、統合テスト（integration test）で使用する外部フィクスチャを配置している。
基本方針は次の通りである。

- `.txt` / `.bin`: 元データ
- `.gz` / `.zst` / `.Z` / `.lz4` / `.lzo` / `.lrz`: 元データを各形式で圧縮したファイル
- `.tar` / `.cpio` / `.lzh`: 複数エントリや形式固有のメタデータを検証するためのアーカイブ
- `fuzz/`: ファズテストで検出された回帰ケースを最小化して保存したファイル

## 命名規則

- `hello.*`: 最小の固定文字列サンプル
- `repeated.*`: 繰り返しパターンを持つ圧縮向きサンプル
- `large.*`: ブロックやサイズ境界の検証を目的とした大きめのサンプル
- `*_original_compress_*`: 元データを外部ツールで圧縮し、その出力を crate 側で検証する回帰テスト用データ
- `*_original_decompress_*`: crate 側で圧縮した出力を外部ツールで展開して検証する回帰テスト用データ

---

## Fixture provenance

以下に、各フィクスチャの元データおよび生成手順を記す。

### `gzip/`

- `hello.txt`
  - 元データは ASCII 文字列 `Hello, World!`
- `hello.gz`
  - `hello.txt` を gzip で圧縮したもの
  - integration test では gzip デコードと、ヘッダーを剥がした raw DEFLATE デコードの両方に使う
- `repeated.txt`
  - 元データは `"The quick brown fox jumps over the lazy dog. "` を 10 回連結した 450 バイトのテキスト
- `repeated.gz`
  - `repeated.txt` を gzip で圧縮したもの
  - 繰り返しパターンに対する圧縮系テストに使う

### `brotli/`

- `signed_context_mode_q10.br`
  - `(i * 7 + 19) % 256` で生成した 256 バイトを system `brotli -q 10` で圧縮したもの
  - context 計算バグ（p1/p2 取り違え）の回帰用（ツール不要）
- `utf8_context_table_q5.br`
  - `(i * 73 + 19) % 256` で生成した 512 バイトを system `brotli -q 5` で圧縮したもの
  - UTF-8 context table バグの回帰用（ツール不要）

### `zstd/`

- `zstd_hello.txt`
  - 元データは ASCII 文字列 `Hello, World!`
- `zstd_hello.zst`
  - `zstd_hello.txt` を zstd で圧縮したもの
- `zstd_repeated.txt`
  - 元データは `"The quick brown fox jumps over the lazy dog. "` を 10 回連結したテキスト
- `zstd_repeated.zst`
  - `zstd_repeated.txt` を zstd で圧縮したもの
- `zstd_large.txt`
  - 1,400 バイトの長めの ASCII テキスト
  - 小さな hello/repeated だけでは見えないフレーム・ブロック境界付近の挙動確認用
- `zstd_large.zst`
  - `zstd_large.txt` を zstd で圧縮したもの

- `seekable_text.bin` / `seekable_text.zst`
  - 元データは `line NNNNNN of the quick brown fox sample` を 900 行連結した 37800 バイトのテキスト
  - `.zst` は参照ツール `contrib/seekable_format/examples/seekable_compression` (frame size 4096, Checksum_Flag=1) で生成した seekable zstd ストリーム
- `seekable_bin.bin` / `seekable_bin.zst`
  - 元データは `i*i mod 7919` (u32 LE) を 6000 個連結した 24000 バイトのバイナリ
  - `.zst` は同ツール (frame size 8192, Checksum_Flag=1) で生成

### `tar/`

- `single_file.tar`
  - 単一エントリ `hello.txt` を含む tar
  - 中身は `Hello from tar!`
- `multi_file.tar`
  - 3 エントリ構成の tar
  - `a.txt` = `File A content`
  - `b.txt` = `File B content`
  - `subdir/nested.txt` = `Nested file`
- `ustar_simple.tar`
  - system `tar --format=ustar` 相当の UStar fixture
  - `hello.txt` = `Hello from UStar!`
  - `data.txt` = `UStar content`
- `gnu_longname.tar`
  - GNU longname 拡張を使う fixture
  - 100 バイト超の path を含むファイルを tar 化したもの
  - GNU `L` header の decode を確認する
- `pax_extended.tar`
  - system `tar --format=posix` 相当の PAX fixture
  - `hello.txt` = `Hello from PAX`
  - `data.txt` = `PAX data content`

### `combined/`

- `multi_file.tar.gz`
  - `tar/multi_file.tar` をそのまま gzip 圧縮したもの
  - gunzip 後のバイト列は `tar/multi_file.tar` と一致する
  - gzip → tar の積み重ね decode を確認する

### `cpio/`

- `single_file.cpio`
  - 単一エントリの SVR4 `newc` cpio fixture
  - エントリ名は `cpio_hello.txt`
  - 中身は `Hello from cpio!`
- `bin_multi.cpio`
  - GNU cpio 2.15 `cpio -o -H bin` で生成した SVR4 binary 形式 fixture (LE u16)
  - エントリ: `data.bin` (36B)、`hello.txt` (22B)、`odd.bin` (1B)
- `bin_mixed.cpio`
  - 同ツール生成。エントリ: `subdir/nested.txt` (20B)、`link.txt` (symlink → `hello.txt`)、`hello.txt` (22B)

### `lha/`

- `level1.lzh`, `level2.lzh`, `level1_nested.lzh`, `level2_nested.lzh`
  - LHa for UNIX 1.14i (jca02266/lha, `lha a -o1` / `-o2`) が生成した `-lh0-` (stored) アーカイブ
  - `level1`/`level2` は `f1.txt` (`hello level one`+改行) と `f2.txt` (`payload2`+改行) の 2 エントリ
  - `*_nested` は `dir/sub/deep.txt` (`nested content`+改行) を先頭に持ち、拡張ヘッダ `0x02` の生 `0xff` 区切りディレクトリを含む
- `lh1.lzh`, `lh1_lharc.lzh`, `lh2.lzh`, `lh3.lzh`
  - `-lh1-`/`-lh2-`/`-lh3-` アーカイブ (`lh2`/`lh3` はローカルで合成、参照ツールとの byte-for-byte 照合済み)。これらのメソッドは権利クリーンな format 参照が存在しないため **意図的に非対応** であり、decode が `Error::Unsupported` を返すことの reject 入力として残置 (`test_lha_legacymethod_rejection`)
- その他の 28 ファイル (`lh*.lzh`, `lz*.lzh`/`lz*.lzs`, `pm*.lzh`/`pm*.pma`, `h2_*`, `h3_*`, `long.*`, `lzs.lzh`, `mtcd.pma` 等)
  - lhasa (fragglet, ISC) のテストコーパスを無改変で vendor したもの
  - LHA 1.14i / LHA OS/2 2.08 / LHarc 1.13 / LArc 3.33 / PMarc / lhmelt / lha_amiga 等が生成したプログラム出力 (ISC ライセンス配布物)
  - known-answer decode 入力。provenance は `THIRD_PARTY_NOTICES` の lha 項と §4a lhasa 項を参照

### `lzw/`

- `hello.Z`
  - `Hello, World!` を system `compress` で `.Z` 化した fixture
  - Unix `compress` 互換確認用

### `lz4/`

- `hello.lz4`
  - `hello from lz4` を system `lz4` で圧縮した fixture
  - system `lz4` 出力の decode 互換確認用

### `lzo/`

- `hello.lzo`
  - `hello from lzop` を system `lzop` で圧縮した fixture
  - lzop ヘッダーとデータブロックの decode 互換確認用

### `lrzip/`

- `hello.lrz`
  - 小さい `.lrz` sample archive
  - crate-local な lrzip container layout を目視確認・手元デバッグするときのサンプルとして保持している
  - system `lrzip` 完全互換を保証するための fixture ではない
  - 生成元は未記録 (初回コミット由来のため crate 生成か system `lrzip` 生成か不明)。ライセンス上の懸念はなし

### `ar/`

- `thin_gnu.a`
  - GNU binutils の `ar rcT` (GPL-3.0-or-later) で生成した thin archive (`!<thin>`) fixture
  - `//` メンバが文字列テーブルペイロードを保持し、通常メンバはヘッダのみの構成

### `arc/`

- `fix8.arc` / `fix9.arc`
  - Debian `arc` 5.21q (GPL-2 系) が生成したプログラム出力 fixture
  - `fix8.arc` は `rnd.bin` = stored (method 2)、`text.txt` = crunched (method 8)
  - `fix9.arc` は `text.txt` = squashed (method 9)
- `rnd.bin` / `text.txt`
  - 上記アーカイブに格納されたメンバの期待内容データ

### `erofs/`

- `mkfs.*.img`
  - `mkfs.erofs` (erofs-utils, GPL-2.0+) で生成したイメージ群
  - uncompressed のほか、lz4/lz4hc/microlzma codec、big pcluster、extents/full-index、ztailpacking、fragments 等の `-E` オプション別バリエーション

### `git-pack/`

- `real.pack` / `real.idx` / `ref.pack`
  - git 2.55 `git repack` (GPL-2.0) が生成した pack/idx fixture
  - decode 回帰と writer 出力の `git index-pack` 相互運用確認に使用

### `iso9660/`

- `bsdtar-plain.iso` / `bsdtar-rockridge.iso` / `bsdtar-joliet.iso` / `bsdtar-eltorito.iso`
  - `bsdtar` (libarchive, BSD-2-Clause) が生成した ISO 9660 イメージ
  - 素の ISO、Rock Ridge、Joliet、El Torito 各バリアントの decode 回帰用

### `lzs/`

- `*.lzs` / `*.expected`
  - この crate 自身のエンコーダで生成した Stac LZS (RFC 2395) ストリームと期待展開データ
  - compcol LZS codec (MIT, KarpelesLab) で相互検証済み (THIRD_PARTY_NOTICES の lzs 項目参照)

### `mppc/`

- `*.pkt` / `*.expected` (`multi.pkts`, `rdp5_stream.pkts`, `wrap_front.pkts` を含む)
  - この crate 自身のエンコーダで生成した MPPC (RFC 2118 / [MS-RDPBCGR] §3.1.8.4) パケットと期待展開データ
  - rdesktop の MPPC デコーダ (GPL-3.0) で相互検証済み
- `external_freerdp_*.pkt` / `*.expected`
  - FreeRDP `TestFreeRDPCodecMppc.c` (Apache-2.0) の圧縮ストリーム定数を埋め込んだ外部エンコーダ由来ベクター (RDP4/RDP5)
  - 詳細は THIRD_PARTY_NOTICES の MPPC 項目を参照

### `mscab/`

- `lzx_mixed.cab` / `lzx_large.cab` / `quantum_flush.cab`
  - cabextract のテスト cabinet 群 (libmspack リポジトリ `cabextract/test/cabs/`, LGPL 2.1) の LZX/Quantum フォルダ由来
  - `lzx_mixed.cab` は `mixed.cab` のフォルダストリームを byte-identical に保った再梱包コンテナ
- `mixed_lzx.lzx` / `mixed_lzx.txt`
  - 同コーパスの `mixed.cab` から取り出した生 LZX フォルダストリームと期待平文
  - `compress::lzx` の decode テストで使用

### `romfs/`

- `genromfs.romfs`
  - `genromfs` 0.5.2 (GPL-2.0+) で生成した romfs イメージ

### `vcdiff/`

- `*_xdelta3.vcd`
  - 参照エンコーダ xdelta3 3.2.0 (Apache-2.0) が生成した VCDIFF (RFC 3284) ストリーム
- `*_src.bin` / `*_tgt.bin`
  - 対応する source/target 入力データ

### `xar/`

- `none.xar` / `md5.xar` / `bzip2.xar` / `real.xar`
  - 参照ツール `xar` 1.6.1 (mackyle/xar, BSD-3-Clause) が生成した fixture 群
  - 詳細は THIRD_PARTY_NOTICES の xar 項目を参照

### `zip/`

- `hw_shrink.zip` / `hw_reduce.zip` / `hw_implode.zip`
  - hwzip 2.4 (Hans Wennborg, public domain) が `payload.bin` を shrink/reduce/implode 各 method で圧縮した fixture
- `payload.bin`
  - 上記 fixture の入力データ (crate 提供)

### `zpaq/`

- `hello.txt`
  - 元データは ASCII 文字列 (68 バイト)
- `hello.upstream-l1.zpaq` / `hello.upstream-l2.zpaq` / `hello.upstream-l3.zpaq`
  - `hello.txt` を upstream libzpaq v7.15 (`Compressor::startBlock(level)`) で圧縮したもの
  - wire 互換の正方向 (upstream 生成 → crate decode) 回帰用
- `empty.upstream-l1.zpaq`
  - 空入力を upstream level 1 で圧縮したもの
- `bin.upstream-l1.zpaq` / `bin.bin`
  - 4,864 バイトのバイナリデータ (全 byte 値を含む) を upstream level 1 で圧縮したものと元データ
- `hello.upstream-stored.zpaq`
  - `n=0` の unmodeled header (HCOMP = HALT のみ) で stored-mode 出力したもの
- `hello.upstream-pcomp-id.zpaq`
  - PROG segment に identity PCOMP (`out; halt`) を載せた upstream stream
  - upstream decoder は EOS の `run(-1)` で OUT が 1 回多く実行されるため末尾に 0xFF が付く — その挙動も含めて検証する
- `hello.upstream-pcomp-inc.zpaq` / `hello.upstream-pcomp-inc.bin`
  - 非 identity PCOMP (`a++; out; halt`) を載せた upstream stream と、upstream 自身の decode 出力
- `jidac-appended-mixed.zpaq`
  - crate `encode_jidac` (2 files) + `JidacAppender` (1 file) + upstream `zpaq a -m1` (1 file) の 3-version JIDAC chain
  - `decode_jidac_appended_mixed` が全 version view と file 内容を検証
- `jidac-m3-heavy-pcomp.upstream.zpaq`
  - upstream `zpaq` CLI v7.15 の `zpaq a fixture.zpaq s400.bin -m3 -threads 1` で生成した JIDAC journaling archive (内部 filename `s400.bin`、409,600 バイト)
  - この archive の PCOMP は EOS (`run(-1)`) で 16,780,266 cycle を要し、旧 cycle limit (1<<24) を超過する — `original-compress` fuzz で検出した境界ケース (seed 1791135713545052870 iter 61) の回帰固定
  - `decode_upstream_jidac_heavy_pcomp` が decode して SHA-1 で内容を検証
- 生成手順: `.local/refs/libzpaq/` (gitignored) の `harness*.cpp` を upstream `libzpaq.cpp` と `-DNOJIT` でコンパイルした oracle、およびコンテナの upstream `zpaq` CLI (`pkg/zpaq`) を使用。逆方向 (crate 生成 → upstream decode) の検証は `ZPAQ_DUMP=1 cargo test` の dump helper + oracle、`ZPAQ_JIDAC_IN=<path>` 環境変数の JIDAC decode helper で再現可能

### `fuzz/`

このディレクトリのフィクスチャは、ファズテストで検出された不具合を再現するための最小化入力である。
人間が判読可能なデータ構造は持たないが、特定の失敗パターンをリグレッションテストとして決定論的に固定・再現する役割を持つ。

`fuzz/generated/` 以下は `archive-fuzz --import-regression` が自動生成する fixtures と、
`tests/integration/generated/` のテストから参照される。ファイル名は失敗シグネチャ由来のため
個別の provenance は記さない。

- `zstd_original_compress_1.bin`
  - fuzz で残した ASCII 寄りの入力データ
- `zstd_original_compress_1.zst`
  - 上の `.bin` を system `zstd` 側で圧縮した対応データ
  - crate 側 decode が system `zstd` 出力を正しく読めるかの回帰用
- `lzip_original_compress_1.bin`
  - fuzz で残したバイナリ入力
- `lzip_original_compress_1.lz`
  - 上の `.bin` を system `lzip -c` で圧縮した対応データ
  - crate 側 decode が system `lzip` 出力を正しく読めるかの回帰用（ツール不要）
- `xz_original_compress_1.bin` / `xz_original_compress_2.bin` / `xz_original_compress_3.bin`
  - fuzz で残したバイナリ入力
- `xz_original_compress_1.xz` / `xz_original_compress_2.xz`
  - 対応する `.bin` を system `xz -c` で圧縮した対応データ
  - crate 側 decode の回帰用（ツール不要）
- `xz_original_compress_3.xz`
  - `xz_original_compress_3.bin` を system `xz -0 -c` で圧縮した対応データ
  - dict_size=256KiB の non-reset chunk 継続（dict boundary）を含むストリームの回帰用（ツール不要）
- `xz_original_decompress_1.bin`
  - fuzz で残した ASCII 寄りの入力
  - crate 側で xz encode した結果を system `xz -dc` で展開できるかの回帰に使う
  - ツール不在時は self-roundtrip のみ検証する
