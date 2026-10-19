---
description: "圧縮ファズテスト実行 → リグレッションテスト作成 → バグ修正"
---

引数: $ARGUMENTS (形式: "<algorithm|all> <duration_seconds>")

共通ルールは `.agents/README.md` を参照。

## Step 1: ファズテスト実行

Podman で 3 本を同時に実行する。x86_64 の SSE2 を名前から省かない。

```sh
make build-container.fuzz
make -j3 fuzz FUZZ_ALGORITHM=<algo> FUZZ_DURATION=<seconds> [FUZZ_PATTERN=<pattern>] [FUZZ_JOBS=<n>]
```

`-j` を付けない `make fuzz` は同じ 3 本を順に実行する。1 本だけ走らせるときは `make fuzz-x86_64` のようにターゲットを指定する。

| ターゲット | バイナリ | 公開経路 | 失敗 | コーパス |
|---|---|---|---|---|
| `fuzz-x86_64` | `archive-fuzz-x86_64` | x86_64 の SSE2 | `fuzz/failures/x86_64/` | `fuzz/corpus/x86_64/` |
| `fuzz-avx2` | `archive-fuzz-avx2` | x86-64-v3 の AVX2 | `fuzz/failures/avx2/` | `fuzz/corpus/avx2/` |
| `fuzz-aarch64` | `archive-fuzz-aarch64`（qemu-user） | aarch64 の NEON | `fuzz/failures/aarch64/` | `fuzz/corpus/aarch64/` |

`FUZZ_ALGORITHM`、`FUZZ_DURATION`、`FUZZ_PATTERN`、`FUZZ_JOBS` は 3 本で共通である。未指定時は全アルゴリズム、60 秒、`--pattern all`、`--jobs 1`。`FUZZ_JOBS` は 1 本の中でアルゴリズムをスレッドに分ける。3 本の同時起動とは別である。各プロセスのソフトアドレス空間は `FUZZ_AS_KB`（既定 2097152、2GiB）である。ハード上限は変えない。外部ツールの子プロセスはソフト上限を 4GiB に上げる。`lrzip` は `LRZIP=NOCONFIG` で起動し、圧縮は `-w 1 -p 1 -m 18`、伸長は `-p 1 -m 18` を付ける。AVX2 は実行時の CPUID では選ばない。ホストに AVX2 が無いとき `fuzz-avx2` は SIGILL で失敗する。

`--pattern all` は `self` と `corrupt` を全アルゴリズムで実行し、ツールがあるアルゴリズムには `original-compress` と `original-decompress` も足す。ツールが無いアルゴリズムへ `original-*` は足さない。

各本の標準エラー末尾に `=== Fuzz Test Summary ===` が出る。`fail` が 0 なら、その本の今回の失敗 artifact は無い。`known` は `fuzz/src/known_issues.rs` のフィルタで、artifact には残らない。実行ディレクトリは `fuzz/failures/<対象>/run-<timestamp>/` である。

前回の artifact が混ざるときは `make clean-fuzz` で `fuzz/failures/` と `fuzz/corpus/` を空にする。今回分だけ見るときは、起動後の `run-*` を対象にする。

ホストの `cargo run --profile fuzz -p archive-fuzz` は、そのホスト向けの既定ビルドである。この環境では x86_64 の SSE2 になる。AVX2 と NEON の確認はコンテナの `fuzz-avx2` と `fuzz-aarch64` で行う。

再現は、失敗した本のディレクトリを渡す。

```sh
cargo run --profile fuzz -p archive-fuzz -- replay fuzz/failures/x86_64/run-.../
```

AVX2 だけで再現する失敗は `archive-fuzz-avx2`、aarch64 だけで再現する失敗は `archive-fuzz-aarch64` で同じ artifact を再生する。

## Step 2: `@fuzz-analyzer` で分析

`@fuzz-analyzer` には、今回の 3 ディレクトリを渡す。

- `fuzz/failures/x86_64/run-*/`
- `fuzz/failures/avx2/run-*/`
- `fuzz/failures/aarch64/run-*/`

見るファイルは `failure-*.json`、`failure-*.bin`、`failure-*.mut.bin`、`hang-*.json`、`hang-*.bin` である。`summary.json`、`manifest.json`、`matrix.json` は集計であり、失敗ケースではない。

3 本の summary を並べる。同じ失敗が 3 本にあれば共有の不具合である。1 本だけにあれば、その公開経路（SSE2、AVX2、NEON）の不具合として扱う。

分類結果:

| 分類 | 対応 |
|------|------|
| バグ (HIGH) | Step 3-4 で即座に修正 |
| バグ (MEDIUM) | Step 3-4 で調査・修正 |
| 既知の非互換 | フィルタ (対応不要) |
| resource oracle 違反 | 性能問題として記録 |

### 既知の非互換 (フィルタリング対象)

正本は `fuzz/src/known_issues.rs` の `classify()`。summary の `known` はこの関数で数えたものである。

| アルゴリズム | パターン | 条件 | 理由 |
|---|---|---|---|
| `lrzip-lzma` `lrzip-bzip2` `lrzip-gzip` `lrzip-lzo` `lrzip-none` `lrzip-zpaq` | `original-decompress` | すべて | system `lrzip` の外側 `.lrz` が非互換 |
| 同上 | `original-compress` | `unsupported compression type`、`unexpected end of input`、`rzip: match offset out of range`、`lrzip-zpaq` の ZPAQL / hcomp | system `lrzip` のコンテナと backend |
| `lzw` `lzw-bits9` | `original-compress` `original-decompress` | 空入力 | `ncompress` が空入力を拒否 |
| `lzw-bits9` | `original-compress` | `mismatch` | `ncompress -b 9` のロッシーな roundtrip |
| `7z` 系 | `original-compress` | 空入力かつ `empty-stream entries are not supported` | 空ストリームエントリは intentional scope |

## Step 3: リグレッションテスト作成

`@fuzz-analyzer` の報告に基づき、`@spec-implementer` でテストを追加する。追加の前に Step 1 の replay で再現を確認する。

- Pattern `self` → `src/compress/<algorithm>/decode.rs` の `#[cfg(test)]`
- Pattern `original-*` → `tests/integration/<algorithm>.rs`
- Pattern `corrupt` → `.mut.bin` を入力に、decode が panic せず終わることを検証する

テスト形式:

```rust
#[test]
fn test_fuzz_regression_<algorithm>_<hash_prefix>() {
    let input: &[u8] = &[/* 失敗入力バイト列 */];
    let encoded = <algorithm>::encode::encode(input);
    let decoded = <algorithm>::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}
```

入力が 1KB 超なら `tests/fixtures/fuzz/` にバイナリを置き、`include_bytes!` で参照する。

## Step 4: バグ修正

`@spec-implementer` でソースコードを修正する。

1. `cargo test test_fuzz_regression_` で失敗を再現する
2. `@fuzz-analyzer` の推定原因を参考に修正する
3. 修正後、失敗した本のバイナリで artifact を replay し、同じアルゴリズムの `make -j3 fuzz` を再実行する
4. コード変更の完了条件は次のとおり
   ```sh
   cargo fmt --all
   make build-container.test && make test
   cargo clippy --all-features --all-targets -- -D warnings
   ```

## Step 5: spec 更新 (必要な場合)

バグ修正で仕様準拠状況が変わった場合、`docs/spec/` を更新する。
`/spec-audit <algorithm>` を実行して整合性を確認する。
