# archive-fuzz

`archive` ライブラリの roundtrip / 外部ツール相互運用 / リグレッション検出を行う fuzz ハーネス。

## クイックスタート

```sh
# 全アルゴリズム、60 秒 (デフォルト)
cargo run --release -p archive-fuzz

# gzip と bzip2 のみ、30 秒
cargo run --release -p archive-fuzz -- --algorithm gzip,bzip2 --duration 30
```

## テストパターン

| パターン | 説明 |
|---------|------|
| `self` | crate で encode → crate で decode |
| `original-compress` | system tool で encode → crate で decode |
| `original-decompress` | crate で encode → system tool で decode |

```sh
# self パターンのみ
cargo run --release -p archive-fuzz -- --pattern self

# original-decompress (外部ツールが必要)
cargo run --release -p archive-fuzz -- --pattern original-decompress
```

外部ツールが見つからない場合、該当パターンを自動的にスキップする。

## 外部ツール一覧

`original-compress` / `original-decompress` パターンおよび統合テスト (`tests/integration/`) の
相互運用性検証で利用する外部ツールの一覧である。環境に導入するツール一覧の正本は `Containerfile` であり、
本表はその導線としての要約である。ツールを追加または更新するときは `Containerfile` を先に変更し、本表を更新する。
なお、アルゴリズムとツールコマンドの対応関係は `fuzz/src/external.rs` の `tool_spec` を正本とする。

### テスト実行時に必要なツール

| ツール (コマンド) | 提供形式 | 主な用途 |
|---|---|---|
| `gzip` | pacman `gzip` | gzip/deflate の interop |
| `bzip2` | pacman `bzip2` | bzip2 の interop |
| `lzip` | pacman `lzip` | lzip の interop |
| `xz` | pacman `xz` | xz / lzma-alone の interop |
| `zstd` | pacman `zstd` | zstd の interop |
| `brotli` | pacman `brotli` | brotli の interop |
| `lz4` | pacman `lz4` | lz4 の interop |
| `lzop` | pacman `lzop` | lzo (lzop container) の interop |
| `lrzip` | pacman `lrzip` | lrzip の interop (完全互換は非保証、known issue 参照) |
| `compress` / `uncompress` | pacman `ncompress` | lzw (`.Z`) の interop |
| `rzip` | PKGBUILD (`pkg/rzip`) | rzip `.rz` の interop |
| `zpaq` | PKGBUILD (`pkg/zpaq`) | zpaq の interop |
| `zip` / `unzip` | pacman `zip`/`unzip` | ZIP の interop |
| `7z` / `7zr` / `7zz` | pacman `7zip` | 7z の interop + arj/arc/lha 等の decode oracle |
| `bsdtar` | pacman `libarchive` | tar/cpio/lha/rpm/xar 等の汎用 oracle |
| `unar` / `lsar` | pacman `unarchiver` | arj/arc の decode oracle |
| `lhasa` | pacman `lhasa` | lha の decode oracle |
| `cabextract` | pacman `cabextract` | mscab の decode oracle |
| `cpio` | pacman `cpio` | cpio の interop |
| `tar` / `ar` | base-devel (GNU binutils/tar) | tar/ar/deb の interop |
| `arc` / `marc` | Debian deb (sha256 pin、`Containerfile` 参照) | arc の oracle |
| `nomarch` | Debian deb (sha256 pin) | arc の decode oracle |
| `mksquashfs` / `unsquashfs` | pacman `squashfs-tools` | squashfs の interop |
| `git` | pacman `git` | git-pack の interop (`index-pack` 等) |
| `python3` | pacman `python` | 独自 oracle スクリプト (pea 等) |

### fixture 生成時のみ必要 (テスト実行時は不要)

`genromfs` (romfs)、`erofs-utils` の `mkfs.erofs`/`fsck.erofs` (erofs)、`xar` 1.6.1 (xar)、
hwzip (zip method 1-6) などのツールは、テスト用 fixture の生成時にのみ必要であり、テスト実行時には不要である。
生成済みの fixture は `tests/fixtures/` に格納している。
各 fixture の由来 (provenance) は `tests/fixtures/README.md` および `THIRD_PARTY_NOTICES` に記載している。

## Coverage-guided モード

`fuzz/corpus/` をシードとしてミューテーションを行い、新規入力を探索する。

```sh
cargo run --release -p archive-fuzz -- \
  --algorithm gzip,zip,7z \
  --mode coverage-guided \
  --jobs 2 \
  --duration 10 \
  --corpus-dir fuzz/corpus
```

新規に観測された入力（novel observation）は `fuzz/corpus/<algorithm>/` に収集する。
`make fuzz`（コンテナ実行）でも `fuzz/corpus/` をマウントするため、収集したコーパスはホスト側に保持される。

## Special case matrix

アーカイブ形式のメタデータ、暗号化、エンコード済みヘッダーの各バリエーションを決定論的に検証する。

対象: `ar`, `tar`, `cpio`, `zip`, `7z` の long-name / metadata / encryption / encoded-header variation。
通常のランダムファズに先立ち、固定ケースとして実行する。

## Resource oracle

正常終了したケースに対しても、実行時間・エンコード後サイズ・デコード後サイズの上限検査を適用する。
想定を超える膨張や過大な実行時間を検出した場合は、失敗としてアーティファクトを生成する。

## Failure artifact

各失敗ケースは最小化および重複排除の後、`.json` と `.bin` のペアとして保存する。

```
fuzz/failures/
  run-<timestamp>/
    manifest.json       — 実行条件、available external tools
    summary.json        — pass/failure/known issue の集計
    matrix.json         — algorithm 別の pattern / special case matrix
    failure-<hash>.json — 再現メタデータ
    failure-<hash>.bin  — 最小化済み入力データ
```

## リプレイとリグレッション化

```sh
# failure をリプレイ
cargo run --release -p archive-fuzz -- --replay fuzz/failures/run-.../failure-....json

# fixture とテスト雛形をエクスポート
cargo run --release -p archive-fuzz -- --export-regression fuzz/failures/run-.../failure-....json

# tests/integration/generated/ へインポート (module index も更新)
cargo run --release -p archive-fuzz -- --import-regression fuzz/failures/run-.../failure-....json
```

`--export-regression` はフィクスチャとテスト雛形のみを出力する。
`--import-regression` はそれに加えて `tests/integration/generated/` のモジュールインデックスも更新する。
外部ツールを要するパターンは `#[ignore]` 属性付きのプレースホルダーとして生成する。

## Known issues

`fuzz/src/known_issues.rs` で意図的な非互換性を管理している。
これらに該当する失敗ケースは、リグレッション報告の対象から除外する。

| アルゴリズム | パターン | フィルタ理由 |
|------------|---------|-----------|
| `lrzip-*` (全 backend) | `original-decompress` | system `lrzip` の outer `.lrz` framing との完全互換を主張しない (intentional scope) |
| `lrzip-*` (全 backend) | `original-compress` | 特定エラー (`unsupported compression type` / `unexpected end of input` / `match offset out of range` / `zpaq: unsupported hcomp opcode`) は system lrzip 側の制限 |
| `lzw`, `lzw-bits9` | `original-compress`, `original-decompress` | `ncompress` は空入力を exit status 2 で拒否する外部ツール固有の動作 |
| `lzw-bits9` | `original-compress` | `compress -b 9` は一部入力でロッシーな roundtrip を起こす外部ツール自身のバグ |
| `7z`, `7z-copy`, `7z-lzma`, `7z-ppmd`, `7z-deflate`, `7z-bzip2` | `original-compress` | system `7z` は空入力を empty-stream エントリーとして格納するが、このエントリー種別は intentional exclusion |

## Resource oracle の注意点

アルゴリズムごとにエンコード後サイズの下限（`min_encoded_floor`）が異なる。
特に `tar-gnu`, `tar-ustar`, `tar-pax` は、GNU tar が常に 20 ブロック × 512 バイト = 10,240 バイト以上を出力するため、下限を 10,240 に設定している。
`cmpsc` (固定 4KiB 辞書 + ヘッダ) と `deb` (ar + 内部 tar ×2 の構造オーバーヘッド) は極小入力でも ~4KiB を超えるため、下限を 8,192 に設定している。

## 対応アルゴリズム

### 圧縮 (43 variant)

| グループ | アルゴリズム名 |
|---------|------------|
| deflate | `deflate` |
| gzip | `gzip`, `gzip-fast`, `gzip-store` |
| zstd | `zstd`, `zstd-fast`, `zstd-best`, `zstd-nochecksum`, `zstd-seekable` |
| bzip2 | `bzip2`, `bzip2-fast`, `bzip2-best` |
| lzip | `lzip`, `lzip-fast`, `lzip-best` |
| lzma | `lzma` |
| xz | `xz`, `xz-fast`, `xz-best` |
| lzw | `lzw`, `lzw-bits9` |
| lz4 | `lz4`, `lz4-fast`, `lz4-best`, `lz4-small-block`, `lz4-block` |
| lzo | `lzo`, `lzo-fast`, `lzo-best` |
| lrzip | `lrzip-lzma`, `lrzip-bzip2`, `lrzip-gzip`, `lrzip-lzo`, `lrzip-none`, `lrzip-zpaq` |
| brotli | `brotli`, `brotli-fast`, `brotli-best` |
| その他 | `snappy`, `rzip`, `zlib`, `zpaq`, `zpaq-level2`, `zpaq-level3` |

### アーカイブ (20 variant)

| グループ | アルゴリズム名 |
|---------|------------|
| ar | `ar`, `ar-bsd` |
| deb | `deb` |
| rpm | `rpm` |
| squashfs | `squashfs` |
| mscab | `mscab` |
| zim | `zim` |
| mtree | `mtree` |
| warc | `warc` |
| git-pack | `git-pack`, `pack` |
| xar | `xar` |
| xca | `xpress`, `xpress-huff`, `lznt1` |
| lzf | `lzf` |
| fastlz | `fastlz` |
| zx0 | `zx0` |
| zx1 | `zx1` |
| zx2 | `zx2` |
| zx5 | `zx5` |
| vcdiff | `vcdiff` |
| mppc | `mppc` |
| lzs | `lzs` |
| lzsa | `lzsa`, `lzsa2` |
| lzrw1a | `lzrw1a` |
| zip | `zip`, `zip-store`, `zip-bzip2`, `zip-zstd` |
| 7z | `7z`, `7z-copy`, `7z-lzma`, `7z-ppmd`, `7z-deflate`, `7z-bzip2` |
| tar | `tar-gnu`, `tar-ustar`, `tar-pax` |
| cpio | `cpio`, `cpio-crc` |

## ライセンス

AGPL-3.0-only
