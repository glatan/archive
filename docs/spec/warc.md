# WARC (Web ARChive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | ISO 28500:2009 (WARC 1.0) / IIPC WARC 1.1 仕様 |
| 形式概要 | `version-line CRLF *(named-field CRLF) CRLF block CRLF CRLF` の繰り返し。version-line は `WARC/1.0` / `WARC/1.1`。named-field は `token ":" SP* value` (LWS folding あり)。block は `Content-Length` octet |
| 実装範囲 | **read のみ** (write は intentional scope 外)。`.warc.gz` は gzip として伸張してから decode する |

参照: WARC 1.1, <https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/>

### レコード構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | `WARC/1.0` / `WARC/1.1` の version line を受け付ける | §WARC 1.1 "WARC file name and record structure" | ✅ | `tolerates_warc_1_0`, `parses_single_record` |
| 2 | それ以外の version line は reject | 同上 | ✅ | `rejects_bad_version` |
| 3 | named-field は `name ":" value`、field name は printable ASCII (制御・空白・`:` 不許可) | §named fields grammar | ✅ | `parse_header_block` |
| 4 | SP/HT で始まる継続行は直前フィールドの値に結合 (LWS folding) | §linear white space | ✅ | `header_folding_joins_value` |
| 5 | header は UTF-8。非 UTF-8 は reject | §record structure (UTF-8 前提) | ✅ | `parse_header_block` |
| 6 | 未知の拡張フィールドは無視してパース継続 | §extension fields ("shall be ignored") | ✅ | `header_folding_joins_value` (X-Custom) |

### 必須フィールド

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | `WARC-Type` 必須 (warcinfo/response/resource/request/metadata/revisit/conversion/continuation 等、値は自由) | §WARC-Type | ✅ | `rejects_missing_mandatory_field` |
| 8 | `WARC-Record-ID` 必須 | §WARC-Record-ID | ✅ | `rejects_missing_mandatory_field` |
| 9 | `WARC-Date` 必須 (W3C ISO 8601 プロファイル文字列として保持) | §WARC-Date | ✅ | `rejects_missing_mandatory_field` |
| 10 | `Content-Length` 必須・非負整数。block はその octet 数 | §Content-Length | ✅ | `rejects_missing_mandatory_field` |
| 11 | block が入力末尾を超える場合は reject | §record structure | ✅ | `rejects_truncated_block` |
| 12 | `WARC-Target-URI` / `Content-Type` は任意フィールドとして保持 | §named fields | ✅ | `parses_single_record` |

### ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | レコード間・末尾の CRLF は許容 (末尾レコードの終端 separator 欠落も許容) | §record structure | ✅ | `empty_stream`, `parses_multiple_records` |
| 14 | エントリ名は `WARC-Target-URI`、欠落時は `WARC-Record-ID` にフォールバック | crate エントリ規約 | ✅ | `parses_multiple_records` |
| 15 | `.warc.gz` (concatenated gzip members) は gzip 伸張後に decode | gzip multi-member | ✅ | `test_warc_gzip_members` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | `WARC/1.0\r\n` / `WARC/1.1\r\n` 先頭で `.warc` を自動検出 | CLI detection | ✅ | `detect_warc` |
| 17 | `archive read` は record を `warc-type` / `content-type` メタデータ付きで一覧化 | CLI semantics | ✅ | `read.rs` の `Format::Warc` アーム |
| 18 | `archive extract` は各 record の block をファイルとして出力 | CLI semantics | ✅ | `extract.rs` の `Format::Warc` アーム |
| 19 | fuzz algorithm `warc` | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 項目 | 理由 |
|---|------|------|
| 20 | ❌ WARC write/encode | read 需要に限定。レコード生成・digest 計算は対象外 |
| 21 | ❌ record 間の `WARC-Concurrent-To` / segment (`continuation`) 結合 | 各 record を独立エントリとして公開。結合は利用側の判断 |
| 22 | ❌ record 内部の HTTP メッセージ解析 (response/request block の中身) | block は opaque octet 列として扱う |
| 23 | ❌ `WARC-Payload-Digest` / `WARC-Block-Digest` の検証 | digest 値の検証は行わない (未知フィールド同様に無視) |
