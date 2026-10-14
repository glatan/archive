# Ascii85

| 項目 | 内容 |
|------|------|
| 形式概要 | 4 octet を 5 文字 (base-85 数字) にエンコードするバイナリ→テキスト形式。Adobe `ASCII85Decode` 変種 (`!`..`u` 空間、`z` 省略、`~>` 終端/`<~ ~>` 括弧) と RFC 1924 の 128bit 固定エンコードの 2 系統がある |
| 基準仕様 | [PDF 32000-1:2008 §7.4.3 ASCII85Decode](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/PDF32000_2008.pdf) (ローカル: `docs/spec/sources/pdf32000_2008.pdf` — **監査メモ: この PDF はテキスト抽出不可のため §7.4.3 の逐語確認は未実施。内容は広く知られた ASCII85 仕様との整合を前提とする**)、[RFC 1924](https://www.rfc-editor.org/rfc/rfc1924.txt) (ローカル: `docs/spec/sources/rfc1924.txt`) |
| 参照実装 | CPython `base64` (PSF License、interop oracle)。詳細: THIRD_PARTY_NOTICES ascii85 項 |
| 実装 | `archive::encoding::ascii85` (encode / decode / encode_rfc1924 / decode_rfc1924)。`ascii85` feature 配下 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| Adobe `ASCII85Decode` | PDF 32000 §7.4.3 | ✅ | ✅ | `<~ ~>` 括弧付き emit、decode は括弧有無両対応 |
| btoa (`xbtoa Begin/End`、`y` 省略) | de facto btoa | ⚠️※ | ❌ | ※ `y` は `Error::Unsupported` で明示拒否、xbtoa 行は未対応 |
| RFC 1924 (128bit→20文字) | RFC 1924 | ✅ | ✅ | `encode_rfc1924` / `decode_rfc1924` (16 octet 固定) |

## Adobe ASCII85Decode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 4 octet → 5 文字、`!`..`u` (33..=117) の連続 alphabet | PDF 32000 §7.4.3 | ✅ | `adobe_roundtrip`、`adobe_wikipedia_example` |
| 2 | `0x00000000` グループは `z` (1文字) で省略可能 | PDF 32000 §7.4.3 | ✅ | `adobe_z_shorthand` |
| 3 | `z` はグループ内に現れてはならない (単独文字) | PDF 32000 §7.4.3 | ✅ | `adobe_z_shorthand` の `9jqz` 拒否 |
| 4 | 最終部分グループ n octet (1-3) は n+1 文字で encode、decode は残り digit を最大値で補完して先頭 n octet を取る | PDF 32000 §7.4.3 | ✅ | `adobe_partial_tail` |
| 5 | 入力中の whitespace は無視 | PDF 32000 §7.4.3 | ✅ | `adobe_whitespace_and_no_delims`。whitespace 集合は SP/TAB/LF/CR/VT(0x0B)/FF(0x0C)。注: PDF 32000 §7.2.2 の white-space 定義は {NUL(0x00),TAB,LF,FF,CR,SP} であり、本実装は VT を追加受理し NUL は alphabet 外として拒否する (PDF 仕様の方向とは逆の軽微差分; pinned PDF はテキスト抽出不可のため normative 確認は未了) (`is_ws`) |
| 6 | `<~` `~>` デリミタ: あってもなくても decode 可能。先頭 `<~` と末尾 `~>` は独立に剥がすため片側のみの入力も受理 | PDF 32000 §7.4.3 | ✅ | `adobe_whitespace_and_no_delims`、`adobe_delimiter_boundaries` (片側デリミタ・空括弧・単独の `~`・データ文字として1文字端数で拒否される単独の `<`)、`adobe_group_boundary_cuts_yield_prefix` (5文字グループ境界での切断は出力接頭辞) |
| 7 | 部分グループ残り 1 文字は不正 | PDF 32000 §7.4.3 | ✅ | `adobe_partial_tail` (`"!"` 拒否) |
| 8 | `y` (btoa 拡張) と alphabet 外文字の拒否 | PDF 32000 §7.4.3 | ✅ | `adobe_rejects_y_and_junk` |
| 9 | 85^5-1 > u32::MAX のグループは参照実装同様 wrap (u64 累積→下位32bit) | 実装選択 | ✅ | `adobe_group_overflow_wraps` (`uuuuu` → `142085828`) |
| 10 | encode は `<~` `~>` で括る | PDF 32000 §7.4.3 | ✅ | 全 encode テスト |
| 11 | CPython `base64.a85decode(adobe=True)` で自前出力を復号可能 | de facto interop | ✅ | `test_ascii85_python_a85decode_compat` (統合) |
| 12 | CPython `base64.a85encode(adobe=True)` 出力を decode 可能 | de facto interop | ✅ | `test_ascii85_python_a85encode_decode` (統合) |

## RFC 1924 Base-85

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 13 | alphabet: `0-9 A-Z a-z !#$%&()*+-;<=>?@^_` + backtick + `{|}~` の 85 文字 | RFC 1924 | ✅ | `rfc1924_example` |
| 14 | 16 octet の 128bit 値を 20 文字の big-endian base85 で表現 | RFC 1924 | ✅ | `rfc1924_example` (RFC 例 `4)+k&C#VzJ4br>0wv%Yp`) |
| 15 | encode は 16 octet 以外を拒否、decode は whitespace 除去後 20 文字を要求 | RFC 1924 (固定長) | ✅ | `rfc1924_lengths` |
| 16 | alphabet 外文字の拒否 | RFC 1924 | ✅ | `rfc1924_lengths` |
| 17 | 85^20-1 > u128::MAX のエンコード列は `Error::InvalidData` で reject (checked 累積、wrap/panic しない) | RFC 1924 §4.1 値域 + エラー規約 | ✅ | `rfc1924_overflow_rejected` |
| 18 | git/python 式 (4 octet 単位) base85 との桁順一致検証 | de facto interop | ✅ | `test_ascii85_rfc1924_python_b85_compat` (統合) |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 18 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 0 |
| **合計** | **18** |

variant 表の btoa (decode ⚠️※ / encode ❌) は集計対象外の intentional scope。`y` 省略と `xbtoa Begin/End` 行はいずれも非対応のまま (`y` は `Error::Unsupported` で明示拒否)。

## 出典 / 検証メモ

- Adobe 側は PDF 32000-1:2008 §7.4.3 `ASCII85Decode` (Adobe/ISO 仕様書の寛容な配布版)。RFC 1924 は April Fools' RFC だが alphabet と表現は明確に定義されている。
- 本実装は仕様書からの独立実装。CPython `base64` (PSF License) は test-time oracle のみ・非配布。
- btoa の `xbtoa Begin`/`xbtoa End` 行と `y` 短縮 (0x20202020) は PostScript/PDF 範囲外の拡張として未対応。
