---
description: "仕様・実装・テスト・docs/spec の突合監査"
---

引数: $ARGUMENTS (形式: "<format|all>")

共通ルールは `.agents/README.md` を参照。

**このスキルは調査と spec 更新のみ。ソースコード変更は `/spec-implement` で行う。**

## 検証チェーン

```
仕様書 (RFC/APPNOTE等) → docs/spec/<format>/ → src/ コード → テスト
         Step 2a               Step 2b          Step 2b
```

全 3 層を検証する。Step 2a が「仕様書に書いてあるのに spec に載っていない要件」を、
Step 2b が「spec に載っているのにコードに存在しない実装」を検出する。

## 状態マーカー定義

| マーカー | 意味 | 判定基準 |
|---------|------|---------|
| ✅ | 実装+テスト済み | ソースに関数/処理が存在 AND テストで検証 |
| ⚠️ | 部分実装 | パースのみ (expose なし)、バリデーション不足、SHOULD level |
| ❌ | 未実装 | ソースに該当処理が存在しない |

## Step 1: 対象の列挙

1. 引数が `all` → 全 `docs/spec/<format>/` ディレクトリを対象
2. 単一フォーマット → `docs/spec/<format>/` のみ
3. 対象ファイルの現在の ✅/⚠️/❌ 件数を集計して表示

## Step 2a: 仕様書 → spec の網羅性検証

`@spec-researcher` を起動し、**バージョンピン留めされた仕様書**を読んで `docs/spec/` と突合する。

### 仕様書の入手

仕様書のバージョンと URL は `docs/spec/sources/manifest.json` で管理されている。

1. **ローカルキャッシュを優先**: `docs/spec/sources/<filename>` が存在すれば Read で読む
2. **キャッシュがなければ**: `make fetch-spec-sources` の実行を指示する (agent は WebFetch しない)
3. **URL 取得不可のフォーマット**: manifest の `no_url_available` に記載。コードコメントと spec を対比する

**重要**: manifest.json に記載されたバージョンの仕様書のみを使用すること。
最新版を勝手に取得してはならない。バージョンを変更する場合は manifest.json を更新する。

### 検証手法

仕様書を読んだら:
1. **セクション/節の一覧**を抽出 (例: RFC 1951 なら §3.2.1-§3.2.7)
2. 各セクションの **MUST / SHALL / REQUIRED** 要件を列挙
3. `docs/spec/<format>/` 内 (index `README.md` または子ファイル) に対応する行があるか照合
4. 対応行がない要件 → **仕様欠落候補**として報告

仕様書が取得できないフォーマット (bzip2, LZW, LZO, rzip, lrzip, tar, cpio, ar, sevenz, zpaq) は:
- `docs/spec/<format>/` 内の「基準仕様」「仕様参照」列から逆引きで妥当性を検証
- コードのコメントに引用されている仕様要件が spec に反映されているか確認

### 並行実行

最大 3 つの `@spec-researcher` を同時起動可能。
仕様書の取得が重いフォーマット (zstd: RFC 8878 は長大) は単独起動を推奨。

## Step 2b: spec → コードの実装検証

Step 2a と同じ `@spec-researcher` が続けて実施 (または別 agent で並行):

1. **❌/⚠️ のステータス検証** — grep で実装の有無を確認
2. **✅ の検証** — テスト名/関数名が存在するか確認
   - 引数が `all` → 全 ✅ 項目を検証 (時間がかかっても正確性を優先)
   - 単一フォーマット → 全 ✅ 項目を検証

## Step 3: 調査結果の統合

| 分類 | 検出元 | 次のアクション |
|------|--------|-------------|
| **仕様欠落** | Step 2a | Step 4 で spec に ❌ 行として追加 |
| **仕様差分** | Step 2a | バグとして記録、`/spec-implement` で修正 |
| **spec 不整合** | Step 2b | Step 4 で spec を修正 (テスト名等) |
| **実装消失** | Step 2b | `/spec-implement` で再実装 |
| **テスト未網羅** | Step 2b | `/spec-implement` でテスト追加 |
| **intentional scope** | Step 2a | ❌ のまま維持、備考に理由 |

## Step 4: spec 更新

全調査完了後、spec ファイルを一括更新:

1. 各ファイルの ✅/⚠️/❌ を正確な値に修正
2. 仕様欠落で発見された新規要件行を追加
3. テスト名/関数名の表記揺れを修正
4. 集計テーブルを更新 (各ファイル末尾)
5. `docs/spec/README.md` の全体集計テーブルを更新

集計の正確性を検証:
```sh
for f in docs/spec/*/README.md docs/spec/*/*.md; do
  [ -f "$f" ] || continue
  case "$f" in docs/spec/sources/*) continue;; esac
  ok=$(awk -F'|' '/^\|[[:space:]]*[0-9]+[[:space:]]*\|/ && /\| ✅ \|/' "$f" | wc -l)
  warn=$(awk -F'|' '/^\|[[:space:]]*[0-9]+[[:space:]]*\|/ && /\| ⚠️ \|/' "$f" | wc -l)
  no=$(awk -F'|' '/^\|[[:space:]]*[0-9]+[[:space:]]*\|/ && /\| ❌ \|/' "$f" | wc -l)
  echo "$f: ✅=$ok ⚠️=$warn ❌=$no"
done
```

## Step 5: 報告

```
監査結果:
- 検査した spec ファイル: N
- 検査した仕様書: N (取得成功 N / 取得不可 N)

Step 2a (仕様書 → spec):
  - 仕様書から抽出した MUST/SHALL 要件: N
  - spec に記載あり: N
  - 仕様欠落候補: N 件
  - intentional scope: N 件

Step 2b (spec → コード):
  - 検査した ✅ 項目数: N
  - テスト名/関数名の不整合: N 件
  - 実装消失: N 件
  - ステータス修正: N 件

spec 更新:
  - 新規追加: N 件
  - テスト名修正: N 件
  - ステータス変更: N 件

最終集計:
  ✅: N  ⚠️: N  ❌: N  合計: N
  カバー率: N%
```

❌/⚠️ の実装が必要な場合は `/spec-implement` を推奨する。
