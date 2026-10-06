# yEnc

| 項目 | 内容 |
|------|------|
| 形式概要 | バイトを +42 (mod 256) で回転し、critical 文字のみ `=` エスケープ対にする Usenet 向けバイナリエンコード。`=ybegin`/`=yend` キーワード行でフレームし、単一/マルチパートを持つ |
| 基準仕様 | [yEncode - A quick and dirty encoding for binaries (revised draft 1.3)](http://www.yenc.org/yenc-draft.1.3.txt) (ローカルスナップショット: `docs/spec/sources/yenc-draft_1.3.txt`) |
| 参照実装 | 仕様書から自作した Python 参照実装 (テスト時 interop oracle のみ・非配布)。詳細: THIRD_PARTY_NOTICES yenc 項 |
| 実装 | `archive::encoding::yenc` (encode / encode_part / decode / join_parts)。`yenc` feature 配下 |

## 対応バリアント

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| 単一パート文書 | draft §"Headers and Trailers" | ✅ | ✅ | `encode` / `decode` |
| マルチパート (個別 part) | draft §"Multi-part Encoded Binaries" | ✅ | ✅ | `encode_part` / `decode`。パートの結合は `join_parts` で対応 |

## 内部エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 出力 = (入力 + 42) mod 256 | draft "Encoding Technique" step 2 | ✅ | 全 roundtrip |
| 2 | 出力バイトが NUL(00h)/LF(0Ah)/CR(0Dh)/`=`(3Dh) の場合 `=` + (値+64) でエスケープ | draft "critical characters" + step 3 | ✅ | `escapes_critical` |
| 3 | TAB(09h) は v1.2 で critical から削除 | draft §critical characters 注記 | ✅ | `escapes_critical` (対象外を確認) |
| 4 | 行頭・行末の SP/TAB をエスケープ (1.2 推奨) | draft "(1.2) Careful writers ... encode TAB SPACES if they would appear in the first or last column" | ✅ | `first_col_space_tab_dot_escaped` |
| 5 | 行頭の `.` をエスケープ (NNTP 二重化対策、選択的推奨) | draft "or also encode a DOT in the first column" | ✅ | `first_col_space_tab_dot_escaped` |
| 6 | エスケープ後は任意文字を受理 (`=` に続くバイトを -64-42 復号) | draft "yDecoder implementations should be capable of decoding any character following an escape sequence" | ✅ | `escapes_critical` 系 + python 参照 decoder interop |
| 7 | 行は最大 n=128 文字。critical が n 番目に来た場合エスケープ対ごと同じ行に置き n+1 文字になる | draft "a line cannot end with an escape character, and a line with n+1 characters must end with an encoded critical character" | ✅ | `line_length_rule` |
| 8 | エンコーダ行終端は CRLF | draft "carriage return/linefeed pairs should be written" | ✅ | 全 encode テスト (emit 確認) |

## キーワード行・フレーム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 9 | `=ybegin ` (空白必須) で開始。`size=` と `name=` が必須、欠ける場合はバイナリではなく議論文とみなす | draft "(1.2) If the parameters ... are not present then the =ybegin might be part of a text-message" | ✅ | `rejects_missing_keywords` |
| 10 | `name=` は常に最後のパラメータで行末までが値 | draft "The filename must always be the last item" | ✅ | `get_name` + 全 decode テスト |
| 11 | `=yend` で終端。`size=` 必須 | draft "Trailer lines must ... contain the size" | ✅ | 全 decode テスト |
| 12 | ブロック外のテキストは無視 | draft "yDecoder implementations must ignore any text outside the header/trailer blocks" | ✅ | `ignores_surrounding_text` |
| 13 | データ中の `=y` キーワード行は不正 (`y` は valid なエスケープ結果ではない) | draft "'y' is not a valid encoded critical character" | ✅ | `decode` の keyword 検出 → InvalidData |
| 14 | header `size=`・trailer `size=`・実デコード長の 3 値一致、不一致は破棄 | draft "compare the header size value with both the trailer size value and the actual size" | ✅ | `rejects_size_and_crc_mismatch` |
| 15 | `crc32=` (hex) があれば照合 | draft §"Verifying Integrity" | ✅ | `rejects_size_and_crc_mismatch`。両キー共存時は `crc32` 優先 (`decode.rs:306` の `or_else` 順序) |
| 16 | 末尾に付加された SP/TAB を除去 (transport 損傷耐性) | de facto (1.2 trailing-space 注記の一般化) | ✅ | `strip_line` |

## マルチパート

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 17 | header に `part=`/`total=` を受理。`part=` がある場合次行は `=ypart` 必須 | draft §multipart "the following line must be a ypart keyword line" | ✅ | `multipart_requires_ypart_and_matching_part` |
| 18 | `=ypart begin= end=` の part 範囲 (1-based inclusive) | draft §multipart | ✅ | `multipart_roundtrip` |
| 19 | trailer は `size=<part size>`、`part=` は header と一致必須 | draft §multipart | ✅ | `multipart_requires_ypart_and_matching_part` |
| 20 | part の期待サイズは `end-begin+1`、trailer `size=` と実データ長と照合 | draft "recompute the expected part size from the begin and end keyword values" | ✅ | `multipart_roundtrip` |
| 21 | `pcrc32=` があれば照合 | draft §multipart | ✅ | `encode_part` が emit + decode 検証 |
| 22 | `=ypart` range が全体サイズを超える場合は拒否 | バリデーション | ✅ | `decode` 内 range チェック |
| 25 | `total=` の部分検証: `part > total` を reject、`part == total` なら `=ypart end` == `=ybegin size` を照合 (不在は受理) | draft "(1.2) should be also added" 推奨項目 | ✅ | `multipart_total_validation`。全パートを対象とした集計照合は `join_parts` (要件 23) で実施する |
| 23 | part の結合・順序付け・missing part 検出 | draft §multipart | ✅ | `join_parts` でパート番号順に結合し、欠落したパートは `Error::InvalidData` で拒否する (`join_parts_roundtrip`, `join_parts_detects_missing_part`, `join_parts_reorders`, `join_parts_rejects_name_mismatch`) |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 24 | Subject 行規約 (`"file" 12345 yEnc bytes`) | ❌ intentional scope | transport (NNTP) 層の規約で、文書本体の外 |
| 26 | MIME/メッセージコンテナ内埋め込み | ❌ intentional scope | yenc.org develop.htm の埋め込みガイドは transport 層 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 24 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 2 (intentional scope) |
| **合計** | **26** |
