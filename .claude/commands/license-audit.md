---
description: "アルゴリズム・実装の権利関係とライセンス互換性を監査"
---

引数: $ARGUMENTS (形式: "<format|all|deps>")

共通ルールは `.claude/README.md` を参照。

## 引数

- `<format>` (例: `zip`, `brotli`): 特定フォーマットのみ監査
- `all`: 全フォーマットを監査
- `deps`: 外部依存クレート (fuzz/cli) のライセンスのみ確認

## Step 1: `@license-auditor` で調査

### format 指定時

`@license-auditor` に以下を調査させる:
1. 対象モジュールの provenance 分類 (clean-room / spec-informed / ported / adapted)
2. `THIRD_PARTY_NOTICES` の該当エントリとの整合性
3. 参照した仕様書・参照実装のライセンス
4. アルゴリズムの特許状況

### `all` 指定時

全フォーマットを一括調査。最大 3 つの `@license-auditor` を並行起動:
- Agent A: 圧縮フォーマット (DEFLATE, gzip, zstd, bzip2, lzip, xz 等)
- Agent B: アーカイブフォーマット (tar, cpio, ar, zip, 7z)
- Agent C: 共有コンポーネント (BCJ, Delta, PPMd, crypto, checksum)

### `deps` 指定時

`@license-auditor` に `fuzz/Cargo.toml` と `archive-cli/Cargo.toml` の全依存クレートのライセンスを確認させる。

## Step 2: 問題の分類

| 分類 | 対応 |
|------|------|
| **特許リスク** | 法務確認、回避策検討 |
| **provenance 不整合** | THIRD_PARTY_NOTICES 更新 |
| **ライセンス非互換** | コード除去または再実装 |
| **記載漏れ** | エントリ追加 |
| **問題なし** | 報告のみ |

## Step 3: THIRD_PARTY_NOTICES 更新

問題があった場合のみ更新。`THIRD_PARTY_NOTICES` の §6 Maintenance guidance に従う。

## Step 4: 報告

```
ライセンス監査結果:
- 監査対象: N モジュール
- 特許リスク: N 件 (HIGH: N, LOW: N, NONE: N)
- provenance 不整合: N 件
- ライセンス非互換: N 件
- 記載漏れ: N 件
- THIRD_PARTY_NOTICES 更新: 要 / 不要
```

## 定期実行の推奨

- 新しいフォーマットを追加した後
- 外部依存クレートを追加・更新した後
- upstream source に基づくモジュール (PPMd, ZPAQ 等) を変更した後
