# MacBinary

| 項目 | 内容 |
|------|------|
| 形式概要 | 128 バイトヘッダ (Finder メタデータ + fork 長) の後に Data Fork・Resource Fork をそれぞれ 128 バイト境界でゼロパディングして並べる、古典 Macintosh 転送コンテナ。MacBinary II は offset 101 (Finder flags 下位)/120-121 (secondary header 長)/122-123 (version)/124-125 (CRC-16) を追加 |
| 基準仕様 | [MacBinary II Standard Proposal (24-Jul-1987)](https://files.stairways.com/other/macbinaryii-standard-info.txt) (ローカルスナップショット: `docs/spec/sources/macbinaryii-standard-info.txt`)。元文書: "the new changes to the MacBinary Standard, as generally agreed upon in the MacBinary II Conference 6/21/87 ... Revised 7/24/87" |
| 実装 | `archive::encoding::macbinary` (encode / decode)。`macbinary` feature 配下 |

## 対応バリアント

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| MacBinary II | proposal offsets 101/120-125 | ✅ | ✅ | エンコーダは常に MB II (`version=min=129`) を emit |
| MacBinary I | proposal robustness checks | ✅ | ❌ | MB II CRC 不一致かつ MB I 健全性チェックを満たす場合に受理 (encode は MB II のみ: intentional scope) |

## ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | offset 0/74 はゼロ必須 | proposal "check bytes 0 and 74 to be both zero" | ✅ | `rejects_bad_header` |
| 2 | filename 長 1-63 (offset 1)、値バイトのみ有効 | proposal offset 001/002 | ✅ | `name_length_boundary`、`rejects_bad_header` |
| 3 | type/creator (65-72)、Finder flags 上位 (73)、protected (81) | proposal offsets | ✅ | `roundtrip` |
| 4 | Data/Resource fork 長 (83-90) BE32、上限 0x7FFFFF | proposal "should be in the range of 0-$007F FFFF" | ✅ | `rejects_bad_header` |
| 5 | creation/modification date (91-98) Mac epoch | proposal | ✅ | `roundtrip` |
| 6 | Finder flags 下位 (101) — MB II のみ反映、MB I では 0 | proposal offset 101 | ✅ | `macbinary1_accepted` |
| 7 | secondary header 長 (120-121): 非ゼロなら 128 境界丸めで読み飛ばし | proposal offset 120 | ✅ | `secondary_header_skipped` |
| 8 | `min_version` (123) > 129 は拒否 | proposal "If the minimum version ... is greater than the version that the terminal program was written for" | ✅ | `rejects_high_min_version` (`Error::Unsupported`) |
| 9 | MB II 判定 = 先頭 124 バイトの CRC-16 (CCITT poly 0x1021, init 0) 一致 | proposal "the CRC should match, which means it is a MB II file" | ✅ | `header_crc_verified` + python 参照 encoder interop |
| 10 | MB I フォールバック健全性チェック: byte 82==0、offsets 101-125 全ゼロ | proposal "at minimum check byte 82 to be zero" + "Offsets 101-125 should all be 0" | ✅ | `macbinary1_accepted`、`rejects_bad_header` |

## フォークレイアウト

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 11 | Data Fork → 128 境界 pad → Resource Fork → pad | proposal 冒頭レイアウト記述 | ✅ | `roundtrip`、`empty_forks` |
| 12 | fork 切り詰めは `UnexpectedEof` (末尾 pad 欠落含む) | バリデーション | ✅ | `rejects_truncated` |
| 13 | Get Info comment 長 (99-100): 宣言あれば末尾の comment 分を読み飛ばして受理 (内容は返さない) | proposal offset 099 / FCMT 注記 | ✅ | trailing 判定ロジック |
| 14 | 宣言外の末尾バイトは拒否 | バリデーション | ✅ | `rejects_trailing_garbage` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 15 | Get Info comment (FCMT) の格納・返却 | ❌ intentional scope | proposal 自身が「ほぼ誰も実装していない」と明記 (Apple が read/write 非推奨)。decode は skip のみ |
| 16 | fdLocation (75-80)・window/folder ID の保持 | ❌ intentional scope | proposal もダウンロード時にゼロ化を指示。encode は 0 emit、decode は読み捨て |
| 17 | packed ファイルの自動 unpack (offset 116-119) | ❌ intentional scope | PackIt 等の packed 形式は別 codec |
| 18 | MacBinary I での encode | ❌ intentional scope | MB II が上位互換であり新規 emit の価値なし |
| 19 | MacBinary III | ❌ intentional scope | ドラフト水準で実在ファイル稀少。II との wire 差異が出た時点で再評価 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 14 |
| ⚠️ 部分対応 | 0 |
| ❌ 未対応 | 5 |
| **合計** | **19** |
