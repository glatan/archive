# RFC 1952 (gzip)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952.txt) — GZIP file format specification version 4.3 (ローカルスナップショット: `docs/spec/sources/rfc1952.txt`) |
| 参照実装 | なし (書面仕様のみに基づいて実装)。system `gzip` (GNU gzip、GPL-3.0-or-later) はテスト時の oracle および `tests/fixtures/gzip/` の fixture 生成にのみ使用 |
| 仕様メモ | 仕様にテストベクターは含まれないが、Appendix 8 に CRC32 リファレンス実装 (ポリノミアル `0xEDB88320`) がある |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `0x1F 0x8B` 検証 | RFC 1952 §2.3.1 | ✅ | `test_invalid_magic` |
| 2 | 圧縮方式 CM=8 (deflate) のみ | RFC 1952 §2.3.1 | ✅ | `test_invalid_compression_method` |
| 3 | FLG 予約ビット (5-7) 非ゼロでエラー | RFC 1952 §2.3.1 | ✅ | `test_reserved_flag_bits_rejected` |
| 4 | FTEXT フラグ (無視されること) | RFC 1952 §2.3.1 | ✅ | `test_ftext_flag_ignored` |
| 5 | FHCRC フラグ (ヘッダーCRC16 検証) | RFC 1952 §2.3.1 | ✅ | `test_parse_header_fhcrc`, `test_fhcrc_validation` |
| 6 | FEXTRA フラグ (追加フィールド) | RFC 1952 §2.3.1 | ✅ | `test_parse_header_fextra`, `test_fextra_valid_multiple_subfields`, `test_invalid_extra_rejected` |
| 7 | FNAME フラグ (ファイル名) | RFC 1952 §2.3.1 | ✅ | `test_parse_header_fname` |
| 8 | FCOMMENT フラグ (コメント) | RFC 1952 §2.3.1 | ✅ | `test_parse_header_fcomment` |
| 9 | オプションフィールドの出現順序 (FEXTRA→FNAME→FCOMMENT→FHCRC) | RFC 1952 §2.3.1 | ✅ | `test_parse_header_all_flags` (全フラグ同時設定で順序検証) |
| 10 | 最小ヘッダー (10バイト、フラグなし) パース | RFC 1952 §2.3.1 | ✅ | `test_parse_minimal_header` |
| 11 | ヘッダー短すぎエラー | RFC 1952 §2.3.1 | ✅ | `test_too_short` |
| 12 | CRC32 トレーラー検証 | RFC 1952 §2.3.1 | ✅ | `test_valid_trailer_crc32_and_isize`, `test_crc32_mismatch` |
| 13 | ISIZE トレーラー検証 | RFC 1952 §2.3.1 | ✅ | `test_valid_trailer_crc32_and_isize`, `test_verify_isize_modulo_wrap_accepts_4gib_boundary` |
| 14 | CRC32 不一致エラー | RFC 1952 §2.3.1 | ✅ | `test_crc32_mismatch` |
| 15 | ISIZE 不一致エラー | RFC 1952 §2.3.1 | ✅ | `test_isize_mismatch` |
| 16 | マルチメンバーストリーム | RFC 1952 §2.2 | ✅ | `test_multi_member_gzip`, `test_multi_member_gzip_three_members` |
| 17 | 空データのgzip | RFC 1952 §2.2 / §2.3.1 | ✅ | `test_roundtrip_empty` (エンコーダー) |
| 18 | MTIME フィールド解釈 | RFC 1952 §2.3.1 | ✅ | `test_mtime_xfl_os_fields` |
| 19 | XFL フィールド (2=最大圧縮, 4=最速) | RFC 1952 §2.3.1 | ✅ | `test_mtime_xfl_os_fields`, `test_xfl_fast_compression` |
| 20 | OS フィールド | RFC 1952 §2.3.1 | ✅ | `test_mtime_xfl_os_fields` |
| 21 | CRC32 既知ベクター (`"123456789"` → `0xCBF43926`) | RFC 1952 Appendix 8 | ✅ | `test_crc32_known_vectors` |
| 22 | CRC32 空データ (`""` → `0x00000000`) | RFC 1952 Appendix 8 | ✅ | `test_crc32_empty` |
| 23 | CRC32 インクリメンタル計算 | RFC 1952 Appendix 8 | ✅ | `test_crc32_incremental` |
| 24 | エンコード→デコード ラウンドトリップ | RFC 1952 §2.2 / §2.3.1 | ✅ | `test_roundtrip_hello`, `test_roundtrip_compressed`, `test_gzip_roundtrip_large` |
| 25 | ISIZE の 2^32 modulo ラップ | RFC 1952 §2.3.1 | ✅ | `test_verify_isize_modulo_wrap_accepts_4gib_boundary`, `test_verify_isize_modulo_wrap_mismatch` |
| 26 | FHCRC CRC16 検証 (RFC 1952 §2.3.1.2) | RFC 1952 §2.3.1 | ✅ | `test_fhcrc_validation` |
| 27 | XFL エンコーダ値 (0x02=最大, 0x04=最速) | RFC 1952 §2.3.1 | ✅ | `test_xfl_values` |
| 28 | マルチメンバー: 異なる圧縮レベル | RFC 1952 §2.2 | ✅ | `test_multi_member_different_compression` |
| 29 | FNAME ヌル終端なしエラー | RFC 1952 §2.3.1 | ✅ | `test_fname_unterminated` |
| 30 | FCOMMENT ヌル終端なしエラー | RFC 1952 §2.3.1 | ✅ | `test_fcomment_unterminated` |
| 31 | FEXTRA データ切り詰めエラー | RFC 1952 §2.3.1 | ✅ | `test_fextra_truncated` |
| 32 | FEXTRA XLEN=0 (空) | RFC 1952 §2.3.1 | ✅ | `test_fextra_xlen_zero` |
| 33 | FNAME 空 (ヌル終端のみ) | RFC 1952 §2.3.1 | ✅ | `test_fname_empty` |
| 34 | FCOMMENT 空 (ヌル終端のみ) | RFC 1952 §2.3.1 | ✅ | `test_fcomment_empty` |
| 35 | DEFLATE ストリーム切り詰めエラー | RFC 1952 §2.2 / §2.3.1 | ✅ | `test_truncated_deflate_stream` |
| 36 | gzip ストリーム境界の NLEN 検証 | RFC 1951 §3.2.4 (embedded DEFLATE stream) | ✅ | `find_deflate_end` 内で検証 |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 37 | FNAME/FCOMMENT は ISO 8859-1 (Latin-1) | RFC 1952 §2.3.1 | ✅ | decoder は内容を解釈せずスキップ (GzipHeader に保持しない)。encoder は Latin-1 / NUL 不在を検証 (encoder_tests) |
| 38 | FEXTRA sub-field 構造: SI1(1B) + SI2(1B) + LEN(2B) + data | RFC 1952 §2.3.1.1 | ✅ | `test_fextra_valid_multiple_subfields`。SI2=0 は将来使用のため予約 (RFC 1952 §2.3.1.1)。注: decoder はサブフィールド構造を検証して malformed を reject (`test_parse_header_invalid_fextra_subfield_rejected`) — RFC 最小要件 (skip 可能であればよい)・GNU gzip より strict |
| 39 | Trailing data after last member の処理 | RFC 1952 §2.2 | ✅ | `decode()` は残余バイトを次メンバーとして `GzipHeader::parse` するため、有効メンバーでない trailing data は `InvalidData` で reject (RFC の厳格解釈)。空入力 `decode(&[])` は `Ok(vec![])` を返す lenient 動作 |
| 40 | エンコーダーは reserved FLG bits を全てゼロに設定 | RFC 1952 §2.3.1.2 | ✅ | encode() で flags=0x00 固定。encode_with_options() は定義済み bit 定数 (FTEXT/FHCRC/FEXTRA/FNAME/FCOMMENT) のみ OR 合成し、bits 5-7 は常に 0 |
| 41 | FNAME は「ディレクトリ要素を除去し小文字化した原本ファイル名」(encoder 側 SHOULD、FS 依存) | RFC 1952 §2.3.1 | ❌ | エンコーダは fname をそのまま格納する intentional scope |
| 42 | XLEN (FEXTRA 長) は u16 — 65535B 超はエンコーダが reject | RFC 1952 §2.3.1.1 | ✅ | `rejects_oversized_extra_field` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 41 |
| ❌ 未実装 | 1 (intentional scope) |
| **合計** | **42** |

