# uuencode

| 項目 | 内容 |
|------|------|
| 形式概要 | バイナリファイルを `begin <mode> <name>` / `end` で囲み、データを最大 45 octet ごとの行に分割して 3 octet → 4 文字 (6bit + 0x20) でエンコードする歴史的テキスト形式 |
| 基準仕様 | [IEEE Std 1003.1-2017 `uuencode`](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/uuencode.html) (ローカルスナップショット: `docs/spec/sources/posix_uuencode_9699919799.html`) |
| 実装 | `archive::encoding::uuencode` (encode / decode)。`uuencode` feature 配下 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| historical algorithm | POSIX.1-2017 STDOUT "uuencode Historical Algorithm" | ✅ | ✅ | 既定アルゴリズム |
| base64 algorithm (`begin-base64` / `====`) | POSIX.1-2017 STDOUT "uuencode Base64 Algorithm" | ✅ | ✅ | `util::base64` (RFC 4648 canonical)。`encode_base64(name, mode, data)` |
| zero 表現: `` ` `` (0x60) / ` ` (0x20) | de facto (GNU sharutils / CPython binascii) | ✅ | ✅※ | decode は両方受理、encode は `` ` `` を emit (POSIX は 0x20 も許容) |

## begin/end 行

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭行は `"begin %s %s\n"` (mode octal + decode_pathname、空白前置なし) | POSIX STDOUT historical | ✅ | `roundtrip_text` |
| 2 | 終端行は `"end\n"` (空白前置なし) | POSIX STDOUT historical | ✅ | `roundtrip_text` |
| 3 | mode は octal として解釈 | POSIX STDOUT | ✅ | `roundtrip_text` (0o644)、`roundtrip_binary_multiline` (0o600) |
| 4 | name (decode_pathname) を `UuEntry::name` として返す | POSIX STDOUT | ✅ | 全 roundtrip テスト |
| 5 | `begin-base64` 文書は `Error::Unsupported` で拒否 | POSIX base64 algorithm | ✅ | `rejects_begin_base64` |
| 6 | `begin` 行なしの入力は拒否 | POSIX STDOUT | ✅ | `rejects_no_begin` |

## データ行

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 7 | 各行は length 文字 (復号 octet 数 + 0x20) + エンコード文字列 | POSIX STDOUT "length character" | ✅ | `roundtrip_binary_multiline` |
| 8 | 1 行あたり最大 45 octet | POSIX STDOUT "maximum ... 45" | ✅ | `line_length_respected` |
| 9 | 3 octet → 4 文字変換式 (`(v & 0x3F) + 0x20`) | POSIX STDOUT 変換式 | ✅ | python `binascii.a2b_uu` interop |
| 10 | 端数 octet グループの decode (1〜2 octet の最終 quad) | POSIX STDOUT 変換式 | ✅ | `roundtrip_text` (14 octets = 4x3+2) |
| 11 | zero 値文字 `` ` `` (0x60) と ` ` (0x20) の両方を受理 | de facto | ✅ | `decodes_space_zero_variant` |
| 12 | length=0 の行 (`` ` `` または ` `) をデータ終端として受理、`end` への橋渡し | de facto (実 uuencode 出力) | ✅ | `roundtrip_empty`、python 生成文書 |
| 13 | データ行 body が length 宣言より短い場合は `UnexpectedEof` | バリデーション | ✅ | `rejects_truncated_body` |
| 14 | `end` 行なしの切り詰めは `UnexpectedEof` | バリデーション | ✅ | `rejects_missing_end` |
| 15 | 行長 > 45 octet 宣言の拒否 | POSIX STDOUT "maximum ... 45" | ✅ | `dec_char`/`decode` の count 検証 |
| 16 | CRLF 行終端の許容 | 頑健性 (非 POSIX) | ✅ | `next_line` の `\r` strip |

## エンコード範囲

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 17 | `encode(name, mode, data)` が `begin` + データ行 + `` ` `` + `end` を出力 | POSIX STDOUT | ✅ | 全 encode テスト |
| 18 | encode の zero 値は `` ` `` (0x60) を emit (GNU sharutils 系 de facto) | de facto | ✅ | `roundtrip_binary_multiline` の decode 経由 |
| 19 | encode は常に 45 octet/行 | POSIX STDOUT | ✅ | `line_length_respected` |
| 20 | python `binascii.b2a_uu` 生成文書 (space zero + ` ` 終端行) の decode | de facto interop | ✅ | `test_uuencode_python_b2a_uu_decode` (統合) |
| 21 | 自前データ行が python `binascii.a2b_uu` で復号可能 | de facto interop | ✅ | `test_uuencode_python_a2b_uu_decodes_ours` (統合) |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 21 |
| ⚠️ 部分対応 | 0 |
| ❌ 未対応 | 0 |
| **合計** | **21** |



## 出典 / 検証メモ

- 仕様書は IEEE Std 1003.1-2017 `uuencode` utilities ページ (The Open Group)。本実装は当該文書から独立実装し、参照実装のコード移植は行っていない。
- interop oracle は CPython `binascii.b2a_uu`/`a2b_uu` (PSF License、テスト時オラクルのみ・非配布)。GNU sharutils の `uuencode`/`uudecode` はコンテナに無いため未使用。
- POSIX 仕様は 0x20..0x5F のみを定義し、`` ` `` 表現と `` ` `` 終端行は de facto 慣習として扱う (sharutils / binascii 出力に一致)。
