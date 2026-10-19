---
description: "開発タスクの分類 → 適切な skill/agent の選択・実行を統括する"
---

引数: $ARGUMENTS (自由記述のタスク説明、または下記のタスク種別キーワード)

共通ルールは `.agents/README.md` を参照。

## 概要

開発タスクを受け取り、タスク種別を判定し、適切な skill/agent を順次実行する統括スキル。
個別 skill を直接呼んでもよいが、`/dev` はどこから始めるべきか迷ったときのエントリーポイント。

## Step 1: タスク種別の判定

引数を分析し、以下のいずれかに分類する。
複数に該当する場合は上から優先して直列実行する。

| 種別 | キーワード例 | 説明 |
|------|------------|------|
| **feature** | 実装, 追加, 新機能, implement | spec の ❌/⚠️ 項目を実装する |
| **fix** | 修正, バグ, fix, regression | 既知のバグを修正する |
| **fuzz** | fuzz, ファズ | ファズテストの実行と結果対応 |
| **audit** | 監査, audit, レビュー, 確認 | spec とコードの整合性を検証する |
| **license** | ライセンス, license, 権利 | ライセンス互換性を検証する |
| **release** | リリース, release, 出荷 | リリース前の品質ゲート |

判定したら「タスク種別: **XXX** — 以下のワークフローで進めます」とユーザーに提示する。

## Step 2: ワークフロー実行

### feature (機能追加)

```
1. /spec-audit <format> --dry-run 相当
   → @spec-researcher で現状の ❌/⚠️ を把握
2. 実装計画をユーザーに提示、承認を得る
3. /spec-implement <format>
   → @spec-researcher + @spec-implementer で実装
4. 最終検証
   cargo fmt --all
   make build-container.test && make test
   cargo clippy --all-features --all-targets -- -D warnings
5. spec 一括同期 (docs/spec/ 更新)
```

### fix (バグ修正)

```
1. バグの再現
   → 該当テストの実行 or 最小再現コードの作成
2. @spec-implementer で修正 + リグレッションテスト追加
3. 最終検証
   cargo fmt --all
   make build-container.test && make test
   cargo clippy --all-features --all-targets -- -D warnings
4. spec 影響確認 (修正が仕様準拠に影響する場合のみ spec 更新)
```

### fuzz (ファズテスト)

```
1. /fuzz <algorithm> <duration>
   → ファズテスト実行 + @fuzz-analyzer で分析
2. バグがあれば @spec-implementer で修正
3. 最終検証
4. spec 影響確認
```

### audit (品質監査)

```
1. /spec-audit <format|all>
   → @spec-researcher で仕様突合
2. 結果報告
   → ❌/⚠️ の実装が必要なら /spec-implement を推奨
```

### license (ライセンス監査)

```
1. /license-audit <format|all|deps>
   → @license-auditor で調査
2. 問題があれば THIRD_PARTY_NOTICES を更新
```

### release (リリース準備)

全ゲートを順次実行する。途中で失敗したらそこで停止し、修正を優先する。

```
1. /spec-audit all
   → 仕様整合性の最終確認
2. /license-audit all
   → ライセンス互換性の最終確認
3. 最終検証
   cargo fmt --all
   make build-container.test && make test
   make check-features
   cargo clippy --all-features --all-targets --workspace -- -D warnings
   cargo doc --all-features --workspace 2>&1 | grep warning
4. (任意) /fuzz all <duration>
   → リリース前ファズテスト
5. ゲート結果サマリーを報告
```

## Step 3: 完了報告

ワークフロー終了後、以下を報告:

```
/dev 完了:
- タスク種別: <type>
- 実行した skill: <list>
- コード変更: あり / なし
- テスト結果: N passed, 0 failed
- spec 更新: あり / なし
- 残タスク: <list or なし>
```

## ガードレール

- **各ステップ間で必ずユーザー承認を挟む** — 自律的に全ステップを連続実行しない
- feature / fix で struct 変更が複数モジュールにまたがる場合、Phase 分割して順次実行
- 最終検証でエラーが出たら、修正してから完了報告する
