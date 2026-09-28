# BinHex

| 項目 | 内容 |
|------|------|
| 形式概要 | `"(This file must be converted with BinHex 4.0)"` プロローグ + `:` + 64 文字アルファベットの 6bit エンコード + 末尾 `:` で構成される古典 Macintosh 転送形式。内部は `0x90` マーカー RLE で圧縮され、header + data fork + resource fork がそれぞれ CRC-16 (poly 0x1021, init 0, 2 ゼロバイト拡張) で終端される |
| 基準仕様 | [BinHex 4.0 Definition (Peter N Lewis, Aug 1991)](https://files.stairways.com/other/binhex-40-specs-info.txt) (スナップショット: `docs/spec/sources/binhex-40-specs-info.txt`)、[RFC 1741 Appendix A](https://datatracker.ietf.org/doc/html/rfc1741) |
| 実装 | `archive::encoding::binhex` (encode / decode)。`binhex` feature 配下 |

## テキスト層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | プロローグ行 `(This file must be converted with BinHex 4.0)`、decode は "with BinHex" までだけ照合して残りを skip | Lewis "only check the string up to 'with BinHex'" | ✅ | `roundtrip`、`prologue_variants` |
| 2 | プロローグなしで `<return>:` で始まる文書も受理 | Lewis "you may choose to ignore ... start when you get `<return>:<hex-chars>`" | ✅ | `prologue_variants` (bare `:` doc) |
| 3 | 6bit 文字アルファベット `!"#$%&'()*+,-012345689@ABC...pqr` (index 0-63) | Lewis alphabet 定義 / RFC 1741 | ✅ | `alphabet_is_unique` + roundtrip |
| 4 | ビット列 MSB-first → 6bit グループ → 文字、残り <8bit は切り捨て | Lewis/RFC bit 詰め規則 | ✅ | `sixbit_roundtrip_boundary` |
| 5 | `<cr><lf><tab><spc>` はデータ中どこでも無視 | Lewis `<return>` 定義 | ✅ | `prologue_variants` (CRLF 混在) |
| 6 | エンコード行長: 先頭行 `:`+63 文字 = 64、以降 64 文字 | Lewis "the first line should be 64 characters long, including the colon" | ✅ | encode emit 検証 |
| 7 | 64/アルファベット以外の文字はエラー | Lewis "any character other than those 64 ... indicates an error" | ✅ | `rejects_invalid_chars` |
| 8 | 末尾 `:` 直前のレガシー `!` 1 個を許容して読み飛ばす (途中の `!` はアルファベット index 0 のデータ文字) | Lewis "Some old programs produced an extra exclamation mark" | ✅ | `prologue_variants` (legacy `!`) |
| 9 | 末尾 `:` なしの切り詰めは拒否 | バリデーション | ✅ | `rejects_crc_and_truncation` |

## RLE 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 10 | `X 90 n` → X を計 n 回に展開 (marker 手前の 1 バイトを含む) | RFC 1741 "11 22 90 06 → 6 個の 22" | ✅ | `rfc1741_examples` |
| 11 | `90 00` → リテラル 0x90 | Lewis/RFC | ✅ | `rle_roundtrip_runs` |
| 12 | `90 00` 直後の run は 0x90 自身を展開 | Lewis "*** Note: the 9000 can be followed by a run" | ✅ | `rle_roundtrip_runs` (2B90009005→2B+90×5) |
| 13 | マーカー直前にバイトがない / マーカーで終端 → 拒否 | バリデーション | ✅ | `rle_malformed` |
| 14 | エンコーダは 4 以上の run をパケット化 (3 以下はリテラル)、0x90 は常に `90 00` エスケープ | de facto 実装方針 (RFC "encoding is made for 3->255" との整合: 効率同一で保守側) | ✅ | `rle_roundtrip_runs` (n=1,2,3,4,10,300 境界) |

## fork 層・CRC

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | header: name len(1B) + name + 0x00 + TYPE + AUTH + FLAG + DLEN + RLEN + CRC | Lewis ヘッダ図式 | ✅ | `roundtrip` |
| 16 | name 長 1-63、終端 0x00 必須 | Lewis | ✅ | `rejects_*` 系 |
| 17 | CRC-16 poly 0x1021 init 0、body + `00 00` を含めて計算 (空 fork は 0x0000) | Lewis "continue the CRC calculation with two 0x00 bytes" | ✅ | `test_binhex_crc_matches_python_crc_hqx` (CPython `binascii.crc_hqx` oracle) |
| 18 | header/data/rsrc の 3 系統 CRC を全て照合 | Lewis | ✅ | `rejects_crc_and_truncation` |
| 19 | fork 長超過・切り詰め・末尾ゴミは拒否 | バリデーション | ✅ | `rejects_crc_and_truncation` |
| 20 | OnDesk(0x0001)/Invisible(0x4000)/Initted(0x0100) を decode 時にクリア | Lewis "the OnDesk, Invisible, and Initted flags should be cleared" | ✅ | `flags_cleared_on_decode` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 21 | `--- end of part NN ---` セグメント分割 | ❌ intentional scope | comp.binaries.mac の分割は transport 層。連結は呼び出し側 |
| 22 | Hqx8 (8bit 形式) | ❌ intentional scope | Lewis 定義の補助形式。実在流通はほぼ Hqx7 |
| 23 | filename の OS 依存サニタイズ (`.`→bullet、`:`→`-` 等) | ❌ intentional scope | Lewis は decode 側 OS 依存規則と明記。name は生値を返す |
| 24 | BinHex 4.0 より古い/別のバリアント (1.x-3.x, .hcx) | ❌ intentional scope | 4.0 が唯一のデファクト標準 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 20 |
| ⚠️ 部分対応 | 0 |
| ❌ 未対応 | 4 |
| **合計** | **24** |
