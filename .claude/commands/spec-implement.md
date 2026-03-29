---
description: "docs/spec/ の ❌/⚠️ 項目を実装 → テスト → spec 更新"
---

引数: $ARGUMENTS (形式: "<format|all> [--dry-run]")

共通ルールは `.claude/README.md` を参照。

## Step 1: 対象の特定

`@spec-researcher` を起動し、対象フォーマットの ❌/⚠️ 項目を調査:

1. 各項目を分類:
   - **A: 実装可能** — 既存 codec/infrastructure で実現できる
   - **B: 要調査** — アルゴリズム理解や設計判断が必要
   - **C: intentional exclusion** — 実装しない (理由を明記)
2. `--dry-run` 時はここで止まり、分類結果と実装計画を出力する

## Step 2: 実装計画の策定

対象 A の項目について:

1. **変更ファイルの列挙** — 各項目がどのファイルを変更するか特定
2. **struct 衝突の検出** — 同じ struct に field を追加する項目をグループ化
3. **Phase 分割** — struct 変更を含むグループは順次実行、独立した変更は並行可能
4. **`@spec-implementer` 割り当て** — 1 agent あたり最大 3 項目 (同一モジュールの変更に限定)

## Step 3: Phase ごとの実装

各 Phase で:

### 3a. `@spec-implementer` 起動

agent に明確な指示を与える:
- 変更対象ファイルのパス
- 追加すべき関数/型/テストの名前

### 3b. 完了確認

`@spec-implementer` 完了後、**必ず** 以下を実行:

```sh
cargo check --all-features
grep -c "<expected_function>" <expected_file>
cargo test --all-features
```

### 3c. エラー修正

コンパイルエラーがあれば `@spec-implementer` を再起動:
- `cargo check --all-features 2>&1` の出力を全て渡す
- 「全エラーと警告をゼロにすること」を指示

## Step 4: 全 Phase 完了後の最終検証

```sh
cargo fmt --all
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-features --all-targets --workspace -- -D warnings
cargo doc --all-features --workspace 2>&1 | grep warning
```

## Step 5: spec 一括同期

全実装完了後、spec ファイルを直接編集して更新:

1. 実装した各項目の spec 行を ❌ → ✅ / ⚠️ → ✅ に変更
2. テスト名を備考欄に追記
3. 各ファイルの集計テーブルを更新
4. `docs/spec/README.md` の全体集計テーブルを更新

**spec 更新時にはソースコードを変更しない。**

## 並行実行の制約

| 条件 | 最大並行数 |
|------|-----------|
| 異なるモジュールの `@spec-implementer` | 3 |
| 同じ struct に field を追加 | 1 (順次) |
| spec ファイルの更新 | 1 |
