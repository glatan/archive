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

外部ツールが見つからない場合、該当パターンは自動的にスキップされます。

## Coverage-guided モード

`fuzz/corpus/` を seed に mutation し、新しい入力を探索します。

```sh
cargo run --release -p archive-fuzz -- \
  --algorithm gzip,zip,7z \
  --mode coverage-guided \
  --jobs 2 \
  --duration 10 \
  --corpus-dir fuzz/corpus
```

novel observation は `fuzz/corpus/<algorithm>/` に harvest されます。
`make fuzz` (コンテナ実行) でも `fuzz/corpus/` をマウントするため、harvest された corpus はホスト側に残ります。

## Special case matrix

アーカイブ形式の metadata / encryption / encoded-header variation を deterministic に検証します。

対象: `ar`, `tar`, `cpio`, `zip`, `7z` の long-name / metadata / encryption / encoded-header variation。
通常の random fuzz の前に固定ケースとして実行されます。

## Resource oracle

正常終了したケースにも runtime / encoded size / decoded size の上限チェックを適用します。
異常な膨張や過大 runtime は failure として artifact 化されます。

## Failure artifact

各 failure は最小化・重複排除後に `.json` + `.bin` ペアとして保存されます。

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

`--export-regression` は fixture とテスト雛形だけを出力します。
`--import-regression` はそれに加えて `tests/integration/generated/` の module index も更新します。
external tool が必要な pattern は `#[ignore]` 付きの placeholder として生成されます。

## Known issues

`fuzz/src/known_issues.rs` で意図的な非互換性を管理しています。
これらに該当する failure はリグレッション報告から除外されます。

| アルゴリズム | パターン | フィルタ理由 |
|------------|---------|-----------|
| `lrzip-*` (全 backend) | `original-decompress` | system `lrzip` の outer `.lrz` framing との完全互換を主張しない (intentional scope) |
| `lrzip-*` (全 backend) | `original-compress` | 特定エラー (`unsupported compression type` / `unexpected end of input` / `match offset out of range`) は system lrzip 側の制限 |
| `lzw`, `lzw-bits9` | `original-compress`, `original-decompress` | `ncompress` は空入力を exit status 2 で拒否する外部ツール固有の動作 |
| `lzw-bits9` | `original-compress` | `compress -b 9` は一部入力でロッシーな roundtrip を起こす外部ツール自身のバグ |
| `7z`, `7z-copy`, `7z-lzma`, `7z-ppmd`, `7z-deflate`, `7z-bzip2` | `original-compress` | system `7z` は空入力を empty-stream エントリーとして格納するが、このエントリー種別は intentional exclusion |

## Resource oracle の注意点

アルゴリズムごとに encoded size の下限 (`min_encoded_floor`) が異なります。
特に `tar-gnu`, `tar-ustar`, `tar-pax` は GNU tar が常に 20 ブロック × 512 バイト = 10240 バイト以上を書き出すため、下限を 10240 に設定しています。

## 対応アルゴリズム

### 圧縮 (43 variant)

| グループ | アルゴリズム名 |
|---------|------------|
| deflate | `deflate` |
| gzip | `gzip`, `gzip-fast`, `gzip-store` |
| zstd | `zstd`, `zstd-fast`, `zstd-best`, `zstd-nochecksum` |
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
| xca | `xpress`, `xpress-huff`, `lznt1` |
| lzf | `lzf` |
| zip | `zip`, `zip-store`, `zip-bzip2`, `zip-zstd` |
| 7z | `7z`, `7z-copy`, `7z-lzma`, `7z-ppmd`, `7z-deflate`, `7z-bzip2` |
| tar | `tar-gnu`, `tar-ustar`, `tar-pax` |
| cpio | `cpio`, `cpio-crc` |

## ライセンス

AGPL-3.0-only
