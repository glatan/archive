# BinHex

| 項目 | 内容 |
|------|------|
| 形式概要 | `"(This file must be converted with BinHex 4.0)"` プロローグ + `:` + 64 文字アルファベットの 6bit エンコード + 末尾 `:` で構成される古典 Macintosh 転送形式。内部は `0x90` マーカー RLE で圧縮され、header + data fork + resource fork がそれぞれ CRC-16 (poly 0x1021, init 0, 2 ゼロバイト拡張) で終端される |
| 基準仕様 | [BinHex 4.0 Definition (Peter N Lewis, Aug 1991)](https://files.stairways.com/other/binhex-40-specs-info.txt) (スナップショット: `docs/spec/sources/binhex-40-specs-info.txt`)、[RFC 1741 Appendix A](https://datatracker.ietf.org/doc/html/rfc1741) |
| 参照実装 | CPython `binascii.crc_hqx` (PSF License、oracle)、独自 Python 参照エンコーダ (oracle)。詳細: THIRD_PARTY_NOTICES binhex 項 |
| 実装 | `archive::encoding::binhex` (encode / decode / `decode_parts`)。`binhex` feature 配下 |

## テキスト層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | プロローグ行 `(This file must be converted with BinHex 4.0)`、decode は "with BinHex" までだけ照合して残りを skip | Lewis "only check the string up to 'with BinHex'" | ✅ | `roundtrip`、`prologue_variants` |
| 2 | プロローグなしで `<return>:` で始まる文書も受理 | Lewis "you may choose to ignore ... start when you get `<return>:<hex-chars>`" | ✅ | `prologue_variants` (bare `:` doc) |
| 3 | 6bit 文字アルファベット `!"#$%&'()*+,-012345689@ABC...pqr` (index 0-63) | Lewis alphabet 定義 / RFC 1741 | ✅ | `alphabet_is_unique` + roundtrip |
| 4 | ビット列 MSB-first → 6bit グループ → 文字、残り <8bit は切り捨て | Lewis/RFC bit 詰め規則 | ✅ | `sixbit_roundtrip_boundary` |
| 5 | `<cr><lf><tab><spc>` はデータ中どこでも無視 | Lewis `<return>` 定義 | ✅ | `prologue_variants` + `roundtrip` (空白・改行混入を skip) |
| 6 | エンコード行長: 先頭行 `:`+63 文字 = 64、以降 64 文字。末尾 `:` は最終データ文字と同行 (最終行 2-65 文字) — 行がちょうど満杯でも `:` は単独行にしない | Lewis "the first line should be 64 characters long, including the colon" + "the last line must be between 2 and 65 characters" | ✅ | `encode_wraps_at_64_columns`, `encode_final_colon_on_last_line` |
| 7 | 64/アルファベット以外の文字はエラー | Lewis "any character other than those 64 ... indicates an error" | ✅ | `rejects_invalid_chars` |
| 8 | 末尾 `:` 直前のレガシー `!` 1 個を許容して読み飛ばす (途中の `!` はアルファベット index 0 のデータ文字)。`!`+`:` の終端は曖昧なので、まず legacy drop で parse、失敗すれば `!` をデータ文字として retry | Lewis "Some old programs produced an extra exclamation mark" | ✅ | `prologue_variants` (legacy `!`)、`encode_final_colon_on_last_line` (末尾 `!` データの roundtrip) |
| 9 | 末尾 `:` なしの切り詰めは拒否 | バリデーション | ✅ | `rejects_crc_and_truncation`、`rejects_all_truncations` (終端の `:` より前の全切断位置でエラー、`:` を保持する切断は受理) |
| 21 | `--- end of part NN ---` セグメント分割 | Lewis "Parts" 節 / comp.binaries.mac 慣行 (RFC 1741 に marker 記述なし) | ✅ | `decode_parts(&[&[u8]])` が分割ドキュメントを連結 (part 終端 `--- end of part NN ---` と `---` resume marker を行境界でのみ認識し、HQX 本文との誤認を防ぐ)。`segmented_roundtrip`, `segmented_marker_boundaries`, `rejects_bad_segment_marker` |

## RLE 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 10 | `X 90 n` → X を計 n 回に展開 (marker 手前の 1 バイトを含む) | RFC 1741 "11 22 90 06 → 6 個の 22" | ✅ | `rfc1741_examples` |
| 11 | `90 00` → リテラル 0x90 | Lewis/RFC | ✅ | `rle_roundtrip_runs` |
| 12 | `90 00` 直後の run は 0x90 自身を展開 | Lewis "*** Note: the 9000 can be followed by a run" | ✅ | `rle_roundtrip_runs` (2B90009005→2B+90×5) |
| 13 | マーカー直前にバイトがない / マーカーで終端 → 拒否 | バリデーション | ✅ | `rle_malformed` |
| 14 | エンコーダは 4 以上の run をパケット化 (3 以下はリテラル)、0x90 は常に `90 00` エスケープ | de facto 実装方針 (RFC "encoding is made for 3->255" との整合: 効率同一で保守側) | ✅ | `rle_roundtrip_runs` (通常バイト n=1-4 の literal/packetize 境界 + 0x90 run n=1,2,3,10,300) |

## fork 層・CRC

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | header: name len(1B) + name + 0x00 + TYPE + AUTH + FLAG + DLEN + RLEN + CRC | Lewis ヘッダ図式 | ✅ | `roundtrip` |
| 16 | name 長 1-63、終端 0x00 必須 | Lewis | ✅ | `rejects_bad_name` (len 0 / 64 / NUL 欠落) |
| 17 | CRC-16 poly 0x1021 init 0、body + `00 00` を含めて計算 (空 fork は 0x0000) | Lewis "continue the CRC calculation with two 0x00 bytes" | ✅ | `test_binhex_crc_matches_python_crc_hqx` (CPython `binascii.crc_hqx` oracle) |
| 18 | header/data/rsrc の 3 系統 CRC を全て照合 | Lewis | ✅ | `rejects_crc_and_truncation` |
| 19 | fork 長超過・切り詰め・末尾ゴミは拒否 | バリデーション | ✅ | `rejects_crc_and_truncation` |
| 20 | OnDesk(0x0001)/Invisible(0x4000)/Initted(0x0100) を decode 時にクリア | Lewis "the OnDesk, Invisible, and Initted flags should be cleared" | ✅ | `flags_cleared_on_decode` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 22 | Hqx8 (8bit 形式) | ❌ intentional scope | 8bit エンコード変種 (Lewis/RFC 本文は Hqx7 のみ記述、Hqx8 は外部資料での呼称)。実在流通はほぼ Hqx7 |
| 23 | filename の OS 依存サニタイズ (`.`→bullet、`:`→`-` 等) | ❌ intentional scope | Lewis は decode 側 OS 依存規則と明記。name は `from_utf8_lossy` で String 化して返す (非 UTF-8 バイトは U+FFFD 置換) |
| 24 | BinHex 4.0 より古い/別のバリアント (1.x-3.x, .hcx) | ❌ intentional scope | 4.0 が唯一のデファクト標準 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 21 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 3 (intentional scope) |
| **合計** | **24** |
