# WARC (Web ARChive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [IIPC WARC 1.1 仕様](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/) (実際の参照ソース、ローカルスナップショット: `docs/spec/sources/warc_1.1.html`)。WARC 1.0 側は ISO 28500:2009 の版番号参照のみで、規格本文は未参照 |
| 参照実装 | なし (書面仕様のみに基づいて実装) |
| 形式概要 | `version-line CRLF *(named-field CRLF) CRLF block CRLF CRLF` の繰り返し。version-line は `WARC/1.0` / `WARC/1.1`。named-field は `token ":" SP* value` (LWS folding あり)。block は `Content-Length` octet |
| 実装範囲 | read/write 両対応 (record stream)。`.warc.gz` は gzip として伸張/圧縮してから decode/encode する |

参照: WARC 1.1, <https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| WARC 1.0 | ISO 28500:2009 (版番号参照のみ、本文未参照) | ✅ | ✅ | write は `WarcEncoder::warc10()` |
| WARC 1.1 | [IIPC WARC 1.1](https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/) | ✅ | ✅ | `WarcEncoder` / `encode` |
| `.warc.gz` (gzip ラップ) | WARC + gzip | ✅ | ✅ | gzip 層は呼び出し側の責務 |

### レコード構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | `WARC/1.0` / `WARC/1.1` の version line を受け付ける | §WARC 1.1 "WARC file name and record structure" | ✅ | `tolerates_warc_1_0`, `parses_single_record` |
| 2 | それ以外の version line は reject | 同上 | ✅ | `rejects_bad_version` |
| 3 | named-field は `name ":" value`、field name は printable ASCII (制御・空白・`:` 不許可) | §named fields grammar | ✅ | `rejects_bad_field_name` (DEL 0x7f 漏れを `is_ascii_graphic` に修正済み) |
| 4 | SP/HT で始まる継続行は直前フィールドの値に結合 (LWS folding) | §linear white space | ✅ | `header_folding_joins_value` |
| 5 | header は UTF-8。非 UTF-8 は reject | §record structure (UTF-8 前提) | ✅ | `rejects_non_utf8_header` |
| 6 | 未知の拡張フィールドは無視してパース継続 | §extension fields ("shall be ignored") | ✅ | `header_folding_joins_value` (X-Custom) |

### 必須フィールド

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | `WARC-Type` 必須 (warcinfo/response/resource/request/metadata/revisit/conversion/continuation 等、値は自由) | §WARC-Type | ✅ | `rejects_missing_mandatory_field` |
| 8 | `WARC-Record-ID` 必須 | §WARC-Record-ID | ✅ | `rejects_missing_mandatory_field` |
| 9 | `WARC-Date` 必須 (W3C ISO 8601 プロファイル文字列として保持) | §WARC-Date | ✅ | `rejects_missing_mandatory_field` |
| 10 | `Content-Length` 必須・非負整数。block はその octet 数 | §Content-Length | ✅ | `rejects_missing_mandatory_field` |
| 11 | ブロックが入力末尾を超える場合は拒否 | §record structure | ✅ | `rejects_truncated_block`、`truncated_prefix_invariant` (任意の切断位置でエラーまたは正当なレコード接頭辞) |
| 12 | `WARC-Target-URI` / `Content-Type` は任意フィールドとして保持 | §named fields | ✅ | `parses_single_record` |

### ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | レコード間・末尾の CRLF は許容。block 後の終端 separator はレコード間・末尾を問わず検証しない | §record structure | ✅ | `tolerates_missing_trailing_separator` |
| 14 | エントリ名は `WARC-Target-URI`、欠落時は `WARC-Record-ID` にフォールバック | crate エントリ規約 | ✅ | `parses_multiple_records` |
| 15 | `.warc.gz` (concatenated gzip members) は gzip 伸張後に decode | gzip multi-member | ✅ | `test_warc_gzip_members` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | record grammar `version CRLF *(named-field CRLF) CRLF block CRLF CRLF` を emit、必須フィールド `WARC-Type`/`WARC-Record-ID`/`WARC-Date`/`Content-Length` を自動生成 | §record structure + 各 mandatory 節 | ✅ | `roundtrip_single`, `roundtrip_multiple` |
| 17 | `WARC-Record-ID` は `<uri>` 形式。裸の URI は自動で `<>` 付与、既に括弧済みならそのまま | §WARC-Record-ID grammar | ✅ | `record_id_gets_brackets` |
| 18 | `WARC-Block-Digest: sha1:<base32(RFC4648,padなし)>` を block 全体に対して発行 (既定 ON、`block_digest(false)`/extra_fields で上書き可) | §WARC-Block-Digest | ✅ | `block_digest_is_emitted_and_correct`, `block_digest_can_be_disabled_or_overridden` |
| 19 | `WARC-Payload-Digest` は caller が payload バイトを供給した時のみ発行 (application/http の entity-body 特定は caller 責務、block は opaque)。payload 不明な record には付けない | §WARC-Payload-Digest | ✅ | `payload_digest_only_when_given` |
| 20 | `WARC/1.0` 版も emit 可能 (`warc10()`)。field name は token (printable ASCII・`:`/空白不可)、value は CR/LF 不許可、managed field (Type/ID/Date/Content-Length/Target-URI/Content-Type) の extra_fields 重複は reject | §named fields grammar | ✅ | `warc10_version`, `rejects_bad_fields` |
| 27 | `WARC-Block-Digest` の decode 時検証 (sha1 + RFC 4648 base32 decode)。`WARC-Payload-Digest` は payload==block が確定できる record のみ検証 (application/http・revisit・segmented/truncated は skip)。sha1 以外の algo label は受理して検証しない | §WARC-Block-Digest / §WARC-Payload-Digest | ✅ | `verify_digest`/`verify_digests` (decode.rs)、`verifies_block_digest`, `rejects_wrong_block_digest`, `rejects_malformed_block_digest`, `skips_unknown_digest_algorithm`, `verifies_payload_digest_for_opaque_block`, `skips_payload_digest_when_payload_not_block` |

### 検証 (record 単位)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 28 | record type 別フィールド使用制約: `WARC-Concurrent-To`/`WARC-IP-Address` (warcinfo・conversion・continuation で禁止)、`WARC-Refers-To` (metadata/revisit/conversion で許容)、`WARC-Refers-To-Target-URI`/`-Date` (revisit のみ)、`WARC-Warcinfo-ID` (warcinfo で禁止)、`WARC-Target-URI` (warcinfo 禁止・response 等で必須)、`WARC-Filename` (warcinfo only)、segment フィールド (continuation only) | WARC 1.1 §5 named fields | ✅ | `rejects_field_forbidden_on_record_type`, `accepts_field_on_allowed_record_type`, `rejects_missing_target_uri` |
| 29 | segmentation 検証 (Clause 7): continuation は `WARC-Segment-Origin-ID`+`WARC-Segment-Number` (>=2) 必須、非 continuation の Segment-Number は 1 のみ、ファイル内系列で number 連番・Total-Length で系列クローズ・累積長照合。cross-file 系列の途中観測は寛容 | WARC 1.1 Clause 7 | ✅ | `accepts_segmented_series`, `rejects_continuation_missing_segment_fields`, `rejects_bad_segment_number`, `rejects_total_length_mismatch`, `rejects_segment_after_total_length`, `accepts_late_joined_segment_series` |
| 30 | segment ('continuation') 結合: `decode::join()` で origin + continuation 系列を単一論理 record に連結 (orphan continuation は pass-through、Total-Length 照合) | WARC 1.1 Clause 7 | ✅ | `join_merges_segmented_series`, `join_passes_orphan_continuations`, `join_unsegmented_is_identity`, `join_rejects_bad_total_length` |
| 31 | `WARC-Concurrent-To` グルーピング: `decode::concurrent_groups()` で capture group を index 集合として解決 | WARC 1.1 §5 named fields | ✅ | `concurrent_groups_links_capture_members` |
| 32 | field name の照合は case-insensitive ("names are not case-sensitive")。必須フィールド・型別制約・digest 検証・extension field 保持のいずれでも case 違いを同一フィールドとして扱う | WARC 1.1 §named fields grammar | ✅ | 実装済み — named-field は parse 時に小文字正規化され、全 lookup (必須フィールド・型別制約・digest・segmentation) が case-insensitive。`field_names_are_case_insensitive` |

| 33 | `WARC-Profile` は revisit record で必須・他 record type では未定義 (未知 profile URI を持つ record は解釈してはならない) | WARC 1.1 §5 named fields / §6 revisit | ✅ | `rejects_revisit_without_profile`, `accepts_revisit_with_profile`, `test_warc_rejects_revisit_missing_profile`, `test_warc_rejects_profile_on_non_revisit`, `test_warc_accepts_revisit_with_known_profile`。未知 profile URI は pass-through (block を解釈しないため "shall not interpret" を自明に充足) |
| 34 | `WARC-Identified-Payload-Type` は well-defined payload を持つ record にのみ使用可 (payload 不明確な record では使用禁止) | WARC 1.1 §5 named fields | ✅ | warcinfo/metadata で禁止 (payload 定義のある response/resource/request/revisit/conversion/continuation は受理)。`accepts_identified_payload_type_on_payload_records`, `test_warc_identified_payload_type_needs_payload` |
| 35 | warcinfo record の `Content-Type` は `application/warc-fields` 必須 | WARC 1.1 Clause 8 | ✅ | decode は missing/mismatch を `InvalidData`、encode も同値を強制 (未指定時は default emit)。Clause 8 は metadata record にも同一 shall を課すが、§6.5 が metadata の `Content-Type` を "may be used" と推奨に留める仕様内矛盾があるため metadata 側は未強制。`rejects_warcinfo_without_warc_fields_type`, `warcinfo_content_type_is_enforced`, `test_warc_rejects_warcinfo_wrong_content_type`, `test_warc_encoder_warcinfo_content_type` |

| 36 | `WARC-Payload-Digest` にも同一の well-defined payload 制約 ("shall not be used on records without a well-defined payload") が課される | WARC 1.1 §5 named fields | ✅ | warcinfo/metadata で禁止 (#34 と同型、`FORBIDDEN_FIELD_TYPES` 登録。digest 検証より先に constraint reject)。`rejects_payload_digest_on_metadata_and_warcinfo`, `rejects_field_forbidden_on_record_type`, `test_warc_payload_digest_needs_payload`, `verifies_payload_digest_for_opaque_block` (resource 化して digest 検証経路を維持) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 21 | `WARC/1.0\r\n` / `WARC/1.1\r\n` 先頭で `.warc` を自動検出 | CLI detection | ✅ | `detect_warc` |
| 22 | `archive read` は record を `warc-type` / `content-type` メタデータ付きで一覧化 | CLI semantics | ✅ | `read.rs` の `Format::Warc` アーム |
| 23 | `archive extract` は各 record の block をファイルとして出力 | CLI semantics | ✅ | `extract.rs` の `Format::Warc` アーム |
| 24 | fuzz algorithm `warc` | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 項目 | 理由 |
|---|------|------|
| 25 | ❌ record 内部の HTTP メッセージ解析 (response/request block の中身) | block は opaque octet 列として扱う (encode 側も payload 特定は caller 責務)。`WARC-Payload-Digest` が特定不能な record では digest 検証も skip (行 27 参照) |
