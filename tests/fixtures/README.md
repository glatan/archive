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

### `fuzz/`

このディレクトリのフィクスチャは、ファズテストで検出された不具合を再現するための最小化入力である。
人間が判読可能なデータ構造は持たないが、特定の失敗パターンをリグレッションテストとして決定論的に固定・再現する役割を持つ。

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
