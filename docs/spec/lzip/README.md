# lzip (LZMA ベース圧縮フォーマット)

| 項目 | 内容 |
|------|------|
| 形式概要 | LZMA アルゴリズムに固定パラメータ (`lc=3`, `lp=0`, `pb=2`) を使用し、6バイトヘッダー + LZMA ストリーム + 20バイトトレーラーで構成される |
| 基準仕様 | [lzip manual 1.26](https://www.nongnu.org/lzip/manual/lzip_manual.html) "File format" (ローカルスナップショット: `docs/spec/sources/lzip_manual_1.26.html`) |
| 参照実装 | なし (書面仕様のみに基づいて実装)。system `lzip` (GNU lzip、GPL-2.0-or-later) はテスト時の oracle としてのみ使用 |

### ストリームフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `LZIP` (4バイト) | lzip manual: File format / Member trailer | ✅ | `test_encode_header_format`, `test_invalid_magic` |
| 2 | バージョン番号 (1バイト, version=1) | lzip manual: File format / Member trailer | ✅ | `test_encode_header_format`, `test_unsupported_version` |
| 3 | 辞書サイズバイト (base = 1<<(ds&0x1F), dict = base - (base>>4)*((ds>>5)&7)) | lzip manual: File format / Member trailer | ✅ | `test_decode_dict_size_basic`, `test_decode_dict_size_with_fraction`, `test_decode_dict_size_max` |
| 4 | 辞書サイズエンコード | lzip manual: File format / Member trailer | ✅ | `test_encode_dict_size_byte` |
| 5 | トレーラー: CRC-32 (4バイト LE) | lzip manual: File format / Member trailer | ✅ | `test_crc_mismatch` |
| 6 | トレーラー: データサイズ (8バイト LE) | lzip manual: File format / Member trailer | ✅ | `test_data_size_mismatch` |
| 7 | トレーラー: メンバーサイズ (8バイト LE) | lzip manual: File format / Member trailer | ✅ | `test_member_size_mismatch` |
| 8 | マルチメンバーストリーム | lzip manual: File format / Member trailer | ✅ | `test_multi_member_roundtrip`, `test_lzip_multi_member` (統合) |
| 9 | 空入力エラー | lzip manual: File format / Member trailer | ✅ | `test_empty_input` |
| 10 | 切り詰めヘッダーエラー | lzip manual: File format / Member trailer | ✅ | `test_truncated_header` |

### LZMA コーデック

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | LZMA パラメータ: lc=3, lp=0, pb=2 | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzip_properties_constant` |
| 12 | リテラル/マッチ/ロングレップ/ショートレップ 状態遷移 | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_state_transitions` |
| 13 | 距離スロットマッピング (0-3直接, 4+コンテキスト) | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_distance_to_slot` |
| 14 | LZMA ラウンドトリップ: 空データ | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_empty` |
| 15 | LZMA ラウンドトリップ: 短いデータ | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_hello` |
| 16 | LZMA ラウンドトリップ: 繰り返しデータ | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_repeated` |
| 17 | LZMA ラウンドトリップ: 全バイト値 | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_all_bytes` |
| 18 | LZMA ラウンドトリップ: 長ラン | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_long_runs` |
| 19 | LZMA ラウンドトリップ: 1KB | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_1kb` |
| 20 | LZMA ラウンドトリップ: 各種サイズ (0-4096) | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_roundtrip_various_sizes` |
| 21 | 破損/途中切断 LZMA ストリーム拒否 | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_truncated_stream_rejected` |
| 22 | EOS マーカー異常 (wrong length/distance) 拒否 | lzip manual: LZMA member payload / shared LZMA semantics | ✅ | `test_lzma_invalid_eos_marker_wrong_length` |

### レンジコーダー

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 23 | 適応確率ビットエンコード/デコード往復 | shared LZMA range coder semantics (lzip payload) | ✅ | `test_range_coder_roundtrip_bits` |
| 24 | 直接ビット (50/50確率) 往復 | shared LZMA range coder semantics (lzip payload) | ✅ | `test_range_coder_roundtrip_direct_bits` |
| 25 | ビットツリー (MSB-first) 往復 | shared LZMA range coder semantics (lzip payload) | ✅ | `test_range_coder_roundtrip_bit_tree` |
| 26 | 逆ビットツリー (LSB-first) 往復 | shared LZMA range coder semantics (lzip payload) | ✅ | `test_range_coder_roundtrip_reverse_bit_tree` |
| 27 | デコーダー: 先頭バイト≠0x00 エラー | shared LZMA range coder semantics (lzip payload) | ✅ | `test_decoder_bad_first_byte` |
| 28 | デコーダー: 入力短すぎエラー | shared LZMA range coder semantics (lzip payload) | ✅ | `test_decoder_too_short` |
| 29 | 正規化: エンコーダーはビット操作後、デコーダーはビット操作前 | shared LZMA range coder semantics (lzip payload) | ✅ | `test_encoder_normalizes_after_bit_operations`, `test_decoder_normalizes_before_bit_operations` |

### lzip エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 30 | ヘッダー形式 (LZIP + version + dict_size) | lzip manual: File format / Member trailer | ✅ | `test_encode_header_format` |
| 31 | エンコード→デコード ラウンドトリップ: 空/hello/repeated/all_bytes/1kb | lzip manual: File format / Member trailer | ✅ | `test_encode_roundtrip_empty`, `test_encode_roundtrip_hello`, `test_encode_roundtrip_repeated`, `test_encode_roundtrip_all_bytes`, `test_encode_roundtrip_1kb` |
| 32 | 辞書サイズ指定エンコード | lzip manual: File format / Member trailer | ✅ | `test_encode_with_larger_dict` |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 33 | system lzip で圧縮したデータのデコード | lzip manual: File format / system `lzip` behavior | ✅ | `test_lzip_decode_system_compressed` (統合) |
| 34 | system lzip -d での展開互換 | lzip manual: File format / system `lzip` behavior | ✅ | `test_lzip_encode_decoded_by_system` (統合) |
| 35 | 大規模データラウンドトリップ | lzip manual: File format / system `lzip` behavior | ✅ | `test_lzip_roundtrip_large` (統合) |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 36 | Dictionary size 範囲: 4KiB (2^12) 〜 512MiB (2^29) | lzip manual | ✅ | dict_size_byte 検証 |
| 37 | LZMA properties 固定値違反 rejection (lc≠3/lp≠0/pb≠2) | lzip manual | ✅ | item 11 で検証 |
| 38 | Trailing data after last member | lzip manual | ✅ | 無視 (lzip manual では reject が規定されておらず、仕様通りの動作) |
| 39 | EOS marker 必須 | lzip manual | ✅ | LZMA decoder で検証 |
| 40 | multimember file 内の empty member (data size = 0) は不許可 | lzip manual ch.5 | ✅ | 実装済み — multimember 内の empty member (data size = 0) を reject。単一メンバーの空ファイルは受理。`test_empty_member_in_multimember_rejected` |
| 41 | member size 上限 (member あたり 2 PiB / 16 EiB−1) | lzip manual ch.5 | ✅ | `MAX_MEMBER_SIZE = 2^51` (2 PiB) を明示。decode は trailer の member size 超過を reject、encode 側も data/member size の上限を検証。`test_decode_rejects_oversized_member` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 41 |
| **合計** | **41** |


---
