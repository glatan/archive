# Benchmark comparison

`archive` の性能を、同じ入力・同じ実効パラメータで参照実装と比較するための
補助レーン。仕様準拠や fuzz の代替ではなく、最適化の判断材料と回帰検出に
使う。

## 実行

```sh
# ホスト上で quick（参照ツールが無い形式は partial / ours-only）
make bench-compare-quick

# ホスト上で full
make bench-compare

# 参照ツールが揃ったテストコンテナ内で full
make bench-compare-container

# 参照実装を固定ソースからビルド（ZX0/1/2/5、LZSA、liblzf、FastLZ、Snappy、LZRW、LZS）
make bench-refs

# 既存 Criterion ベンチ
make bench
```

レポートはホスト実行では `target/bench/compare/run-<unix-nanos>-<pid>/`、
コンテナ実行では `target/bench/container/run-<timestamp>/` に出力される
（`BENCH_OUT` で変更可能）。

- `report.md`: 人間向けの比較表とカバレッジ
- `result.json`: 生サンプル、環境情報、ビルド情報、git commit

`--output-dir` で出力先を変更できる。

```sh
cargo build --release -p archive-cli --bin archive --bin archive-bench-helper
cargo bench --all-features --bench compare -- \
  --quick --format gzip,zstd --corpus text --iterations 3
```

## 測定モデル

| 列 | 内容 |
|---|---|
| `ours-lib` | `archive-bench-helper` がライブラリ呼び出しの前後だけを計測する。プロセス起動・引数解析・入力の読み込み・出力の書き込みは計測区間外 |
| `ours-cli` | codec は `archive compress` / `archive test`、archive は `archive pack` / `archive extract` をサブプロセスとして実行。起動とファイル I/O を含む |
| `ref-cli` | 参照ツールをサブプロセスとして実行。起動とファイル I/O を含む |

`ours-lib` は実装ポテンシャル、`ours-cli` と `ref-cli` は end-to-end の比較に使う。
参照側の decode は `/dev/null` または一時ディレクトリへ出力し、検証時だけ
実ファイルへ出力する。zpaq-archive の CLI decode は `archive test` を使う
（journal tree の再構成はライブラリ側のみ）。

- warmup 1 回 + quick 2 回 / full 5 回のサンプル中央値
- スループットは decimal MB/s（1e6 bytes/s）
- `lib/ref` と `cli/ref` は参照側スループット ÷ 我々のスループット。
  1 より大きいほど参照が速い
- `CV` は encode の我々 / 参照の変動係数。10% を超える場合はノイズを疑う
- 同一マシン内の相対比を使う。絶対値をマシン間で比較しない

### パラメータ正規化

形式ごとに辞書・window・block・checksum・level を可能な限り合わせる。

| 形式 | 我々の既定 | 参照側 |
|---|---|---|
| gzip | level 6 / fixed max_chain=32 | `gzip -6 -n`（実効パラメータは一致しないため注記） |
| zlib / deflate | level 6 / fixed max_chain=32 | CPython zlib level 6（実効パラメータは一致しないため注記） |
| zstd | 32 KiB window / 128 KiB block / checksum | `zstd -3 --zstd=wlog=15 --check -T1` |
| bzip2 | level 9 | `bzip2 -9` |
| lzip | 4 KiB 辞書 | `lzip -6 -s 4096` |
| lzma-alone | 8 MiB 辞書 | `xz --format=lzma --lzma1=dict=8MiB -T1` |
| xz | 4 KiB 辞書 / CRC32 | `xz -6 --lzma2=dict=4KiB --check=crc32 -T1` |
| lz4 | 4 MiB block / block+content checksum / content size | `lz4 -1 -T1 -B7 -BX --content-size` |
| lzo | LZO1X-1 | `lzop -1` |
| fastlz | 入力 64 KiB 以上は level 2 | `fastlz_compress_level(2)` |
| brotli | 既定エンコーダ | `brotli -q 5`（直接対応する level がないため注記） |
| zx0/1/5 | 既定 | 参照 CLI の `-q` |
| zx2 | 既定 | 参照 CLI（`-q` なし） |
| lzsa v1/v2 | 既定 | `lzsa -f 1/2 --prefer-speed` |

参照側の level を複数測る場合は `catalog.rs` にケースを追加する。

### 相互デコード

測定ペアごとに次を確認する。

1. 参照実装の出力を我々が decode し、元データとハッシュ一致
2. 我々の出力を参照実装が decode し、元データとハッシュ一致

失敗は性能値ではなく `cross_decode_ok=false` として記録する。形式の variant が
異なる場合は N/A または partial と理由を記録する。

## コーパス

- codec: `text` / `run` / `random` / `periodic`（`--corpus all` で全種）
- archive: 固定メタデータのファイルツリー（quick 64 files、full 200 files）
- 大容量ファイルは `target/bench` に生成し、リポジトリにはコミットしない
- `--size` で codec の入力サイズを上書きできる（archive のツリーサイズは固定）
  - source-build driver の上限: LZRW / LZS の compress 入力は 1 GiB、decode 入力は LZRW 約 204 MiB / LZS 約 128 MiB。既定サイズは範囲内
- read-only 形式の一部は `target/bench/fixtures/` に生成した fixture を使う
  （deb/rpm/mtree/warc/zim/squashfs/cramfs/pea/mscfb/crx3）。fixture はリポジトリにコミットしない
- fixture の decode は、ディレクトリ entry を除いたファイル payload の集合を
  ours-lib / ours-cli / 参照実装で比較する（ツリー名は比較しない）
- `--timeout` で helper / CLI / 参照プロセスの 1 回あたりの上限を指定できる（既定 600 秒、0 は拒否）
- 7z の archive ケースは、`kEmptyStream` を意図的に未対応としているため、
  ベンチマーク用ツリーから `empty.bin` を除外する

## 参照実装

| 入手方法 | 例 |
|---|---|
| ディストリ配布バイナリ | gzip, zstd, xz, bzip2, lzip, lz4, lzop, brotli, ncompress, rzip, lrzip, 7z, tar, cpio, ar, zip, bsdtar, cabextract, unsquashfs, unar, lhasa, xdelta3 |
| 固定ソースビルド | ZX0/1/2/5, LZSA, liblzf, FastLZ, Snappy, LZRW1/1-A/2/3/3-A, LZS |
| Python stdlib | zlib, deflate, uuencode, Ascii85 |
| 参照なし（N/A） | snappy (framed), zpaq (raw), zstd-seekable, mppc, lzxd, cmpsc, xpress, xpress-huff, lznt1, packbits, yenc, macbinary, binhex |

`make bench-refs` は `docs/bench/refs/build.py` を実行し、
`target/bench/refs/bin/` に参照バイナリを置く。ハーネスは PATH より
`target/bench/refs/bin/` を優先する。ビルド記録は
`target/bench/refs/build-info.json` に残す。ピン留めした revision と
フラグの一覧は [refs/README.md](refs/README.md) を参照。

### 結果の検査

full-reference 実行後は `result.json` の status を検査する。

```sh
python3 docs/bench/check-status.py target/bench/compare/run-.../result.json
# または
make bench-check-status RESULT=target/bench/compare/run-.../result.json
# 参照未導入で partial を許容する場合
make bench-check-status RESULT=... ALLOW_PARTIAL=1
```

- `failed` / `unavailable` / 未知の status があれば exit 1
- `partial` も exit 1（`--allow-partial` で許可）
- `ours-only` は参照実装がないケースとして許容
- CI には接続しないローカル確認用

### ベースライン比較

`--baseline target/bench/compare/run-.../result.json` を指定すると、
同一ケース・同一 corpus・同一入力サイズ・同一 implementation の中央値差分を Markdown に追加する。

- 差分は同一マシン・同一入力サイズ・同一 decode mode・同一ビルド条件でのみ意味がある
- baseline と入力サイズまたは decode mode が一致しない測定は差分表に出さない
- 参照実装の差分も表示する
- CI 連携や性能ゲートは行わない

### ビルドフラグの表示

レポートの `Reference build provenance` 表に次を出す。

- 参照名、バイナリパス
- distro package の version（取得できる場合）
- catalog に記録したビルドフラグと、バイナリの `.comment` にある compiler 情報
- 我々の Rust 側の profile、`RUSTFLAGS`、rustc version、CPU、git commit

ソースビルドの完全な `CFLAGS` / `CXXFLAGS` / `LDFLAGS`、compiler version、
実行コマンド、バイナリ sha256 は `result.json` の `refs_build`
（`build-info.json` の埋め込み）に含まれる。

ソースビルドの既定フラグは
`-O2 -march=x86-64 -mtune=generic -fomit-frame-pointer -g0`。参照の最適化を
変えた場合は `docs/bench/refs/build.py` の `CFLAGS` を変更し、レポートを
再生成する。distro package は実際の `-O` フラグまで公開されないため
`distro package (exact distro build flags not exposed)` と明記する。

### ライセンス

参照実装は **実行のみ**。GPL/LGPL の参照をリンク・同梱しない。
参照ソースは `target/bench/refs/src/` に取得し、リポジトリには置かない。
`THIRD_PARTY_NOTICES` と各形式の `docs/spec/<format>/README.md` の
「参照実装」行に性能比較での用途を記録する。

## カバレッジ

`docs/spec/` にある全形式をカタログに載せる。参照実装があるものは比較し、
ないものは `ours-only` / `partial` / `failed` / `unavailable` として理由を表示する。
全形式の一覧は [reference-matrix.md](reference-matrix.md) を参照。

### 制約

- アーカイブのメタデータ（時刻・パーミッション・拡張フィールド）は
  writer 間で異なる。サイズ比較はその差を含む
- distro package の最適化フラグは不明な場合がある
- 小型入力では参照プロセスの起動時間が支配的になる。形式ごとのサイズクラスを使い、
  遅い codec は 1 MiB、速い codec は 4 MiB 以上を既定にする。ZX/LZSA など
  非常に遅い参照は 32〜512 KiB に落とす
- WSL2 などでは CPU 周波数・スケジューリングのノイズが大きい。CV を確認し、
  必要ならネイティブ Linux で再測定する
- `ours-lib` は CLI の production dispatch を経由するため、純粋な free
  function 呼び出しより少し重い。実装ポテンシャルの下限として読む

## 形式の追加

1. `benches/compare/catalog.rs` に `Case` を追加
2. 必要な参照コマンドを `RefCommand` で定義
3. 参照がソースビルドなら `docs/bench/refs/build.py` に取得・ビルドを追加
4. `cargo bench --all-features --bench compare -- --format <id>` で確認
5. `--list-markdown` で `docs/bench/reference-matrix.md` を再生成
6. `THIRD_PARTY_NOTICES` と該当 `docs/spec/<format>/README.md` を更新
