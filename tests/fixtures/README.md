# Test fixtures

このディレクトリには、integration test で使う外部 fixture を置いています。
基本方針は次の通りです。

- `.txt` / `.bin` は元データ
- `.gz` / `.zst` / `.Z` / `.lz4` / `.lzo` / `.lrz` は、その元データを各形式で圧縮したもの
- `.tar` / `.cpio` は、複数エントリや format-specific metadata を確認するためのアーカイブ
- `fuzz/` は、ファズテストで見つかった回帰ケースを最小化して保存したもの

---

## Fixture provenance

以下は、「どんなデータを」「どう加工して」 fixture にしたかの説明です。

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

このディレクトリの fixture は、意味のある文書や自然言語データではなく、**ファズテストで回帰を再現するために保存した入力** です。
基本的に「最小化された入力」なので、人が読める意味は薄いですが、失敗パターンを固定するのに重要です。

- `zstd_original_compress_1.bin`
  - fuzz で残した ASCII 寄りの入力データ
- `zstd_original_compress_1.zst`
  - 上の `.bin` を system `zstd` 側で圧縮した対応データ
  - crate 側 decode が system `zstd` 出力を正しく読めるかの回帰用
- `lzip_original_compress_1.bin`
  - fuzz で残したバイナリ入力
  - system `lzip -c` に流し、その出力を crate 側で decode する回帰に使う
- `xz_original_compress_1.bin`
  - fuzz で残したバイナリ入力
  - system `xz -c` に流し、その出力を crate 側で decode する回帰に使う
- `xz_original_decompress_1.bin`
  - fuzz で残した ASCII 寄りの入力
  - crate 側で xz encode した結果を system `xz -dc` で展開できるかの回帰に使う

### 命名規則メモ

- `hello.*`
  - 最小の固定文字列サンプル
- `repeated.*`
  - 繰り返しパターンを持つ圧縮向きサンプル
- `large.*`
  - ブロックやサイズ境界を見やすくするための大きめサンプル
- `*_original_compress_*`
  - 元データを外部ツールで圧縮し、その出力を crate 側で受ける回帰
- `*_original_decompress_*`
  - crate 側で圧縮した出力を外部ツールで展開する回帰
