# .agents/ ディレクトリ構成

## 概要

archive crate の開発を支援する agent と skill の定義。
`.agents/skills/` と `.agents/agents/` は agents.md 互換レイアウトで、Devin CLI / Desktop が読み取る。

## アーキテクチャ

```
/dev (統括)
 ├─ /spec-audit     ──→  @spec-researcher
 ├─ /spec-implement ──→  @spec-researcher → @spec-implementer
 ├─ /license-audit  ──→  @license-auditor
 └─ /fuzz           ──→  @fuzz-analyzer → @spec-implementer
```

- `/dev` はタスク種別を判定し、適切な skill を順次実行する統括スキル
- 各 **Skill** はワークフローを定義し、**Agent** を順次/並行で起動する
- Agent は単一の責務だけを持ち、skill のコンテキスト外でも単独起動できる

## Agent 一覧

| Agent | Model | 種別 | 責務 |
|-------|-------|------|------|
| [spec-researcher](agents/spec-researcher.md) | swe-2 | 読み取り専用 | 仕様と実装の突合調査 |
| [spec-implementer](agents/spec-implementer.md) | swe-2 | 書き込み | コード実装・テスト追加 |
| [license-auditor](agents/license-auditor.md) | swe-2 | 読み取り専用 | ライセンス・権利関係の調査 |
| [fuzz-analyzer](agents/fuzz-analyzer.md) | swe-2 | 読み取り専用 | fuzz failure の分析・分類 |

## Skill 一覧

| Skill | 引数 | 説明 |
|-------|------|------|
| [/dev](skills/dev/SKILL.md) | 自由記述 or キーワード | **統括** — タスク種別を判定し適切な skill を実行 |
| [/spec-audit](skills/spec-audit/SKILL.md) | `<format\|all>` | 仕様書→spec→コードの 3 層突合監査 |
| [/spec-implement](skills/spec-implement/SKILL.md) | `<format\|all> [--dry-run]` | spec の ❌/⚠️ 項目を実装 |
| [/license-audit](skills/license-audit/SKILL.md) | `<format\|all\|deps>` | ライセンス互換性の監査 |
| [/fuzz](skills/fuzz/SKILL.md) | `<algorithm\|all> <seconds>` | ファズテスト → 修正 |

## 共通ルール

全 agent・skill が従うルール。個別の agent 定義には固有ルールのみ記載する。

### 言語

- agent の報告・出力は **日本語**

### 検証

- コード変更後は `cargo check --all-features` を実行してから完了報告する
- agent の「完了」報告を鵜呑みにしない — skill 側で grep/read による存在確認を行う
- テスト確認は原則としてコンテナ内 (`make build-container.test && make test`)

### struct 変更の安全策

- struct に field を追加したら `grep -rn "StructName {" src/` で全初期化子を更新する
- 同じ struct を変更する agent は **1 つだけ** にする (並行禁止)

### 見積もり

- アルゴリズム実装の LOC はテスト込みで計画値の **1.5-2x** になる

### spec 更新

- spec ファイル (`docs/spec/`) の更新は**全実装完了後に 1 回だけ**行う
- `@spec-implementer` は spec を変更しない

### 禁止事項 (全 agent 共通)

- `git commit` / `git push` / `git stash` の実行
- `README.md` / `AGENTS.md` / `Cargo.toml` の変更 (必要な場合は報告のみ)
