# archive-fuzz

`archive` ライブラリの roundtrip / 外部ツール相互運用 / リグレッション検出を行う fuzz ハーネス。

## クイックスタート

```sh
# 全アルゴリズム、60 秒 (デフォルト)。`fuzz` profile は release 最適化に
# debug-assertions / overflow-checks を有効化したもの
cargo run --profile fuzz -p archive-fuzz

# gzip と bzip2 のみ、30 秒
cargo run --profile fuzz -p archive-fuzz -- --algorithm gzip,bzip2 --duration 30
```

## テストパターン

| パターン | 説明 |
|---------|------|
| `self` | crate で encode → crate で decode |
| `original-compress` | system tool で encode → crate で decode |
| `original-decompress` | crate で encode → system tool で decode |
| `corrupt` | decoder の malformed-input 耐性 (後述) |

```sh
# self パターンのみ
cargo run --profile fuzz -p archive-fuzz -- --pattern self

# corrupt パターンのみ (decoder の malformed-input 耐性)
cargo run --profile fuzz -p archive-fuzz -- --pattern corrupt

# original-decompress (外部ツールが必要)
cargo run --profile fuzz -p archive-fuzz -- --pattern original-decompress
```

外部ツールが見つからない場合、該当パターンを自動的にスキップする。

### corrupt パターンの詳細

`corrupt` は各ケースで次の変異を **決定的シード** (入力由来) で適用し、decode が panic せず
有限のエラー (または上限内の出力) で返ることを検証する。

1. ランダムバイト変異 (`datagen::mutate`) — 4 回
2. prefix 切断スイープ — 小さなストリームは全オフセット、大きなストリームは端点 + 対数間隔サンプル
3. 境界値書き込み — head/tail のフィールド領域 (先頭・末尾 32 バイト) に `0`, `0xFF`, `0xFFFF`, `0xFFFFFFFF` を LE u32 で書き込む
4. 上記と同じスケジュールを、実ツール生成の fixture (`tests/fixtures/`、`--fixtures-dir` で変更可) のうち決定的に選んだ 1 件にも適用する

fixture フェーズではまず **pristine (無変異) の fixture を decode** してベースラインを取る。
pristine で panic すればそのまま finding として報告し、graceful な decode エラーなら
そのファイルはこのアルゴリズムの decode 対象外 (`.expected` 等の補助データや未対応の
upstream バリアント) とみなして変異スケジュールをスキップする。decode 成功時は
出力上限を `max(corrupt_decoded_limit(fixture サイズ), pristine 出力サイズ × 4)` に設定する
ため、大きな fixture が正当な大出力を返しても誤検出にならない。

fixture はコミット済みの静的ファイルであり、self-encoded ストリームでは到達しない
vendor 拡張や実際のマルチエントリレイアウトを decoder 経路として網羅する。
fixture が存在しない環境では fixture フェーズのみスキップする。

失敗した場合、失敗を起こした **変異後ストリームそのもの** が `.mut.bin` sidecar として保存され、
`mut_file` / `mutation` (例: `fixture#19/truncate@226589`) が `.json` に記録される。
`--replay` は `.mut.bin` があればそれを直接 decode して再現性を確認するため、
replay は fixture の有無や encode 経路に依存しない。

### レベルエイリアス

`*-fast` / `*-best` 系バリアント (`zstd-fast`, `lz4-best` 等) は内部 encode/decode が
ベースバリアントと同一であり、外部ツールの圧縮レベル違い (`zstd -1` vs `-19` 等) を
original-* パターンで検証するためのものである。`--pattern all` では self/corrupt を
スキップして外部ツールパターンのみを実行する (明示指定時は従来どおり実行される)。

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
| `7z` / `7zr` / `7zz` | pacman `7zip` | 7z の interop + arj/arc/lha/zip multi-disk 等の decode oracle |
| `bsdtar` | pacman `libarchive` | tar/cpio/lha/rpm/xar 等の汎用 oracle |
| `unar` / `lsar` | pacman `unarchiver` | arj/arc の decode oracle |
| `lhasa` | pacman `lhasa` | lha の decode oracle |
| `cabextract` | pacman `cabextract` | mscab の decode oracle |
| `cpio` | pacman `cpio` | cpio の interop |
| `tar` / `ar` | base-devel (GNU binutils/tar) | tar/ar/deb の interop |
| `arc` / `marc` | PKGBUILD (`pkg/arc`、ソースビルド) | arc の oracle |
| `nomarch` | PKGBUILD (`pkg/nomarch`、ソースビルド) | arc の decode oracle |
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

アーカイブ形式のメタデータ、暗号化、エンコード済みヘッダー、複数エントリの各バリエーションを決定論的に検証する。

対象: `ar`, `tar`, `cpio`, `zip`, `7z` の long-name / metadata / encryption / encoded-header variation に加え、
各アーカイブ系アルゴリズムの `multi-entry` ケース (3 エントリ格納 + payload 回収検証)、
および全 codec アルゴリズムの `determinism` ケース (同一入力の 2 回 encode がバイト一致することを検証)。
通常のランダムファズに先立ち、固定ケースとして実行する。

## Resource oracle

正常終了したケースに対しても、実行時間・エンコード後サイズ・デコード後サイズの上限検査を適用する。
想定を超える膨張や過大な実行時間を検出した場合は、失敗としてアーティファクトを生成する。
`corrupt` パターンでは変異ループ自体が runtime oracle に誤検出されないよう、
実行時間と通常の decode サイズ検査を免除し、変異ごとの decode 出力上限のみを適用する。

## Watchdog

`catch_unwind` は panic を捕捉するが、無限ループや OOM abort はラン全体を止めてしまう。
各ケースは実行前に `inflight-<worker>.json` / `inflight-<worker>.bin` breadcrumb を
run ディレクトリに永続化し、バックグラウンドの watchdog スレッドが予算 (60 秒 +
入力サイズ比例、上限 300 秒) を超えたケースを検出した時点で `hang-w<worker>-i<iter>.{json,bin}`
を書いてプロセスを abort する (exit code 3)。プロセスが先に abort しても breadcrumb
が残るため、ハング・OOM の両方で証跡が残る。
`corrupt` パターンの各変異 probe は in-memory の in-flight エントリを更新する (予算は
probe 毎にリセットされるため、多数の高速 probe を走らせる正当なケースを誤検出しない)。
ネストした `enter` (minimizer 等) も in-memory 更新のみで、外側の breadcrumb を保つ。
abort 時点で実行中だった外部ツールの子プロセスは孤児として残り得る点に注意。

## Failure artifact

各失敗ケースは最小化および重複排除の後、`.json` と `.bin` のペアとして保存する。
`corrupt` パターンの失敗では、失敗を起こした変異後ストリームが `.mut.bin` sidecar として
追加保存される (`.json` の `mut_file` / `mutation` フィールド参照)。
panic の signature には panic 発生位置 (`@ file:line`) が含まれ、独立した panic サイトが
別々のバケットとして重複排除される。

```
fuzz/failures/
  run-<timestamp>/
    manifest.json       — 実行条件、available external tools
    summary.json        — pass/failure/known issue の集計
    matrix.json         — algorithm 別の pattern / special case matrix
    failure-<hash>.json — 再現メタデータ
    failure-<hash>.bin  — 最小化済み入力データ
    failure-<hash>.mut.bin — corrupt 失敗の最小化済み変異ストリーム
    inflight-*.json/bin — in-flight breadcrumb (正常終了時は削除される)
    hang-*.json/bin     — watchdog が検出したハングの証跡
```

## リプレイとリグレッション化

```sh
# failure をリプレイ (corrupt artifact は .mut.bin を直接 decode)
cargo run --profile fuzz -p archive-fuzz -- --replay fuzz/failures/run-.../failure-....json

# .mut.bin を直接指定しても companion .json に解決される
cargo run --profile fuzz -p archive-fuzz -- --replay fuzz/failures/run-.../failure-....mut.bin

# hang-*.json (watchdog artifact) もリプレイ可能: corrupt は記録バイトを
# 直接 decode、他パターンは入力を再実行。まだハングするなら watchdog が abort する
cargo run --profile fuzz -p archive-fuzz -- --replay fuzz/failures/run-.../hang-....json

# ディレクトリ指定で一括リプレイ (非 artifact の json はスキップ)
cargo run --profile fuzz -p archive-fuzz -- --replay fuzz/failures/run-.../

# fixture とテスト雛形をエクスポート
cargo run --profile fuzz -p archive-fuzz -- --export-regression fuzz/failures/run-.../failure-....json

# tests/integration/generated/ へインポート (module index も更新)
cargo run --profile fuzz -p archive-fuzz -- --import-regression fuzz/failures/run-.../failure-....json
```

`--export-regression` はフィクスチャとテスト雛形のみを出力する。
`--import-regression` はそれに加えて `tests/integration/generated/` のモジュールインデックスも更新する。
外部ツールを要するパターンは `#[ignore]` 属性付きのプレースホルダーとして生成する。
`corrupt` artifact は `.mut.bin` があれば実際の decoder 耐性テスト
(「decode が panic せず終了すること」を検証) として生成される。

## Known issues

`fuzz/src/known_issues.rs` で意図的な非互換性を管理している。
これらに該当する失敗ケースは、リグレッション報告の対象から除外する。

| アルゴリズム | パターン | フィルタ理由 |
|------------|---------|-----------|
| `lrzip-*` (全 backend) | `original-decompress` | system `lrzip` の outer `.lrz` framing との完全互換は保証しない (intentional scope) |
| `lrzip-*` (全 backend) | `original-compress` | 特定エラー (`unsupported compression type` / `unexpected end of input` / `match offset out of range` / `zpaq: ZPAQL execution error` / `zpaq: invalid hcomp jump target` / `zpaq: zpaql execution limit exceeded`) は system lrzip 側の制限 |
| `lzw`, `lzw-bits9` | `original-compress`, `original-decompress` | `ncompress` は空入力を exit status 2 で拒否する外部ツール固有の動作 |
| `lzw-bits9` | `original-compress` | `compress -b 9` は一部入力でロッシーな roundtrip を起こす外部ツール自身のバグ (encoder の `n_bits < maxbits` ガードと decoder の無条件 phantom bump が不整合となるため) |
| `7z`, `7z-copy`, `7z-lzma`, `7z-ppmd`, `7z-deflate`, `7z-bzip2` | `original-compress` | system `7z` は空入力を empty-stream エントリーとして格納するが、このエントリー種別は intentional exclusion |

## Resource oracle の注意点

アルゴリズムごとにエンコード後サイズの下限（`min_encoded_floor`）が異なる。
特に `tar-gnu`, `tar-ustar`, `tar-pax` は、GNU tar が常に 20 ブロック × 512 バイト = 10,240 バイト以上を出力するため、下限を 10,240 に設定している。
`cmpsc` (固定 4KiB 辞書 + ヘッダ) と `deb` (ar + 内部 tar ×2 の構造オーバーヘッド) は極小入力でも ~4KiB を超えるため、下限を 8,192 に設定している。

## 対応アルゴリズム

### 圧縮

| グループ | アルゴリズム名 |
|---------|------------|
| deflate | `deflate` |
| gzip | `gzip`, `gzip-fast`, `gzip-store` |
| zstd | `zstd`, `zstd-fast`, `zstd-best`, `zstd-nochecksum`, `zstd-seekable`, `zstd-dict` |
| bzip2 | `bzip2`, `bzip2-fast`, `bzip2-best` |
| lzip | `lzip`, `lzip-fast`, `lzip-best`, `lzip-dict` |
| lzma | `lzma` |
| xz | `xz`, `xz-fast`, `xz-best`, `xz-delta`, `xz-x86`, `xz-powerpc`, `xz-ia64`, `xz-sparc`, `xz-arm`, `xz-armthumb`, `xz-arm64`, `xz-riscv` |
| lzw | `lzw`, `lzw-bits9` |
| lz4 | `lz4`, `lz4-fast`, `lz4-best`, `lz4-small-block`, `lz4-block`, `lz4-dict`, `lz4-legacy`, `lz4-block-dependent` |
| lzo | `lzo`, `lzo-fast`, `lzo-best` |
| lrzip | `lrzip-lzma`, `lrzip-bzip2`, `lrzip-gzip`, `lrzip-lzo`, `lrzip-none`, `lrzip-zpaq` |
| brotli | `brotli`, `brotli-fast`, `brotli-best`, `brotli-metadata` |
| lzrw | `lzrw1`, `lzrw1a`, `lzrw2`, `lzrw3`, `lzrw3a` |
| zx | `zx0`, `zx1`, `zx2`, `zx5` |
| lzsa | `lzsa`, `lzsa2` |
| xca | `xpress`, `xpress-huff`, `lznt1` |
| その他 | `lzf`, `fastlz`, `packbits`, `vcdiff`, `vcdiff-source`, `mppc`, `mppc-rdp4`, `mppc-rdp5`, `lzs`, `lzxd`, `cmpsc`, `snappy`, `rzip`, `zlib`, `zpaq`, `zpaq-level2`, `zpaq-level3` |

### アーカイブ

| グループ | アルゴリズム名 |
|---------|------------|
| ar | `ar`, `ar-bsd` |
| deb | `deb` |
| rpm | `rpm` |
| squashfs | `squashfs` |
| cramfs | `cramfs` |
| romfs | `romfs` |
| erofs | `erofs` |
| iso9660 | `iso9660`, `iso9660-rr` |
| mscab | `mscab` |
| mscfb | `mscfb`, `mscfb-v4` |
| zim | `zim` |
| mtree | `mtree` |
| warc | `warc` |
| zpaq | `zpaq-archive` |
| git-pack | `git-pack`, `git-pack-delta`, `git-pack-sha256` |
| xar | `xar` |
| lha | `lha`, `lha-lh4`, `lha-lh5`, `lha-lh6`, `lha-lh7`, `lha-lzs`, `lha-lz5`, `lha-pm1`, `lha-pm2` |
| arj | `arj`, `arj-1`, `arj-2`, `arj-3`, `arj-4`, `arj-garbled` |
| arc | `arc` |
| pea | `pea`, `pea-store`, `pea-sha256` |
| crx3 | `crx3` (decode-only、fixture 経由で roundtrip/corrupt を検証) |
| zip | `zip`, `zip-store`, `zip-bzip2`, `zip-zstd`, `zip-deflate64`, `zip-lzma`, `zip-xz`, `zip-ppmd`, `zip-shrunk`, `zip-implode`, `zip-reduce` |
| 7z | `7z`, `7z-copy`, `7z-lzma`, `7z-ppmd`, `7z-deflate`, `7z-bzip2`, `7z-deflate64`, `7z-brotli`, `7z-x86`, `7z-bcj2`, `7z-delta` |
| tar | `tar-gnu`, `tar-ustar`, `tar-pax` |
| cpio | `cpio`, `cpio-crc`, `cpio-odc`, `cpio-bin` |

## 意図的スコープ

- **streaming decode**: 各 `decode_reader` API は内部的に `read_to_end` するラッパーであり、
  チャンク境界の読み出しをハーネスから検証する手段がない。実ストリーミング検証は
  ライブラリ側に incremental API が整備されてから対象とする。
- **differential accept/reject**: 外部ツールが受理したがこの crate が拒否する (または逆) ケースの
  差分検出は、外部ツールの終了コード・エラーメッセージが形式間で統一的に比較できないため実装していない。
  現状は original-* の roundtrip 成功のみを oracle とする。
- **CI への組み込み**: 意図的に行わない。ローカルまたはコンテナ内での明示実行を前提とする。
- **cargo-fuzz 統合**: `fuzz_target!` ハーネス化は別クレート + nightly toolchain が前提のため、
  本ハーネスとは別系統の将来検討事項とする。

## ライセンス

AGPL-3.0-only
