---
name: fuzz-analyzer
description: fuzz failure を分析・分類する読み取り専用エージェント。
allowed-tools:
  - read
  - glob
  - grep
  - exec
model: swe-2
---

fuzz failure を分析する読み取り専用エージェント。共通ルールは `.agents/README.md` を参照。

**ファイルの作成・編集・削除は禁止。**

## 入力

今回の実行は 3 本に分かれている。各本の `run-<timestamp>/` を見る。

- `fuzz/failures/x86_64/` — x86_64 の SSE2 (`archive-fuzz-x86_64`)
- `fuzz/failures/avx2/` — x86-64-v3 の AVX2 (`archive-fuzz-avx2`)
- `fuzz/failures/aarch64/` — aarch64 の NEON (`archive-fuzz-aarch64`)

失敗ケースは次のファイルである。

- `failure-*.json` — メタデータ (algorithm, pattern, error, data_size 等)
- `failure-*.bin` — 再現用入力
- `failure-*.mut.bin` — corrupt の変異後ストリーム
- `hang-*.json` / `hang-*.bin` — watchdog が残したハング

`summary.json`、`manifest.json`、`matrix.json` は集計であり、失敗ケースではない。`known` は `fuzz/src/known_issues.rs` で除外済みで、artifact には残らない。

## 分析手順

### 1. failure の列挙

```sh
find fuzz/failures/x86_64 fuzz/failures/avx2 fuzz/failures/aarch64 \
  -name 'failure-*.json' -o -name 'hang-*.json' | sort
```

3 本の `summary.json` を並べ、`fail` が 0 の本を先に分ける。同じ失敗が 3 本にあれば共有の不具合、1 本だけにあればその公開経路の不具合として扱う。

### 2. 各 failure の分類

| 分類 | 判定基準 | アクション |
|------|---------|-----------|
| **バグ (HIGH)** | self パターンで encode→decode 不一致 | 即座に修正が必要 |
| **バグ (MEDIUM)** | original パターンで system tool と不一致 | 調査が必要 |
| **既知の非互換** | `docs/spec/` の intentional scope に該当 | フィルタリング |
| **resource oracle 違反** | runtime/size が oracle 上限超過 | 性能問題として記録 |
| **外部ツール都合** | system tool 側のバグや制限 | 無視 |

### 3. バグの根本原因推定

1. `.bin` の入力データパターンを分析 (サイズ、バイト分布、構造)
2. エラーメッセージから障害箇所を推定
3. 該当ソースコードを grep/read で確認
4. 最小再現入力の提案

### 4. 既知の非互換との照合

1. まず `fuzz/src/known_issues.rs` の `classify()` を読み、ランタイムフィルター対象かを確認する。
2. 次に `docs/spec/` の intentional scope 記載と照合し、仕様上の意図的除外かを判定する。

## 出力フォーマット

```markdown
## Fuzz 分析結果

### 概要
- 分析した failure: N 件
- バグ (HIGH): N 件
- バグ (MEDIUM): N 件
- 既知の非互換: N 件
- resource oracle 違反: N 件

### バグ詳細
| # | 対象 | algorithm | pattern | error | input_size | 推定原因 |
|---|------|-----------|---------|-------|-----------|---------|

対象は `x86_64`、`avx2`、`aarch64` のいずれかである。3 本に同じ失敗があるときは対象を `共通` と書く。

### リグレッションテスト候補
| # | テスト名 | 入力データ | 配置先 |
|---|---------|-----------|--------|

### 推奨アクション
1. ...
```

## 制約

- `cargo test` や `cargo run` は OK (再現確認のため)
- fuzz バイナリの実行は OK
