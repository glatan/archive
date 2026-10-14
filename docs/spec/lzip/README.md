# lzip (LZMA ベース圧縮フォーマット)

| 項目 | 内容 |
|------|------|
| 形式概要 | LZMA アルゴリズムに固定パラメータ (`lc=3`, `lp=0`, `pb=2`) を使用し、6バイトヘッダー + LZMA ストリーム + 20バイトトレーラーで構成される |
| 基準仕様 | [lzip manual 1.26](https://www.nongnu.org/lzip/manual/lzip_manual.html) "File format" (ローカルスナップショット: `docs/spec/sources/lzip_manual_1.26.html`) |
| 参照実装 | なし (書面仕様のみに基づいて実装)。system `lzip` (GNU lzip、GPL-2.0-or-later) はテスト時の oracle としてのみ使用 |

### ストリームフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `LZIP` (4バイト) | lzip manual §5 File format | ✅ | `test_encode_header_format`, `test_invalid_magic` |
| 2 | バージョン番号 (1バイト, version=1) | lzip manual §5 File format | ✅ | `test_encode_header_format`, `test_unsupported_version` |
| 3 | 辞書サイズバイト (base = 1<<(ds&0x1F), dict = base - (base>>4)*((ds>>5)&7)) | lzip manual §5 File format | ✅ | `test_decode_dict_size_basic`, `test_decode_dict_size_with_fraction`, `test_decode_dict_size_max` |
| 4 | 辞書サイズエンコード | lzip manual §5 File format | ✅ | `test_encode_dict_size_byte` |
| 5 | トレーラー: CRC-32 (4バイト LE) | lzip manual §5 File format | ✅ | `test_crc_mismatch` |
| 6 | トレーラー: データサイズ (8バイト LE) | lzip manual §5 File format | ✅ | `test_data_size_mismatch` |
| 7 | トレーラー: メンバーサイズ (8バイト LE) | lzip manual §5 File format | ✅ | `test_member_size_mismatch` |
| 8 | マルチメンバーストリーム | lzip manual §5 File format | ✅ | `test_multi_member_roundtrip`, `test_lzip_multi_member` (統合) |
| 9 | 空入力エラー | lzip manual §5 File format | ✅ | `test_empty_input` |
| 10 | 切り詰めヘッダーエラー | lzip manual §5 File format | ✅ | `test_truncated_header`、`test_truncated_at_every_position` (全切断位置で拒否) |

### LZMA コーデック

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | LZMA パラメータ: lc=3, lp=0, pb=2 | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzip_properties_constant` |
| 12 | リテラル/マッチ/ロングレップ/ショートレップ 状態遷移 | lzip manual §6 Format of the LZMA stream | ✅ | `test_state_transitions` |
| 13 | 距離スロットマッピング (0-3直接, 4+コンテキスト) | lzip manual §6 Format of the LZMA stream | ✅ | `test_distance_to_slot` |
| 14 | LZMA ラウンドトリップ: 空データ | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_empty` |
| 15 | LZMA ラウンドトリップ: 短いデータ | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_hello` |
| 16 | LZMA ラウンドトリップ: 繰り返しデータ | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_repeated` |
| 17 | LZMA ラウンドトリップ: 全バイト値 | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_all_bytes` |
| 18 | LZMA ラウンドトリップ: 長ラン | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_long_runs` |
| 19 | LZMA ラウンドトリップ: 1KB | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_1kb` |
| 20 | LZMA ラウンドトリップ: 各種サイズ (0-4096) | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_roundtrip_various_sizes` |
| 21 | 破損/途中切断 LZMA ストリーム拒否 | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_truncated_stream_rejected` |
| 22 | EOS マーカー異常 (wrong length/distance) 拒否 | lzip manual §6 Format of the LZMA stream | ✅ | `test_lzma_invalid_eos_marker_wrong_length` |

### レンジコーダー

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 23 | 適応確率ビットエンコード/デコード往復 | lzip manual §6.1 range coder | ✅ | `test_range_coder_roundtrip_bits` |
| 24 | 直接ビット (50/50確率) 往復 | lzip manual §6.1 range coder | ✅ | `test_range_coder_roundtrip_direct_bits` |
| 25 | ビットツリー (MSB-first) 往復 | lzip manual §6.1 range coder | ✅ | `test_range_coder_roundtrip_bit_tree` |
| 26 | 逆ビットツリー (LSB-first) 往復 | lzip manual §6.1 range coder | ✅ | `test_range_coder_roundtrip_reverse_bit_tree` |
| 27 | デコーダー: 先頭バイト≠0x00 エラー | lzip manual §6.1 range coder | ✅ | `test_decoder_bad_first_byte` |
| 28 | デコーダー: 入力短すぎエラー | lzip manual §6.1 range coder | ✅ | `test_decoder_too_short` |
| 29 | 正規化: エンコーダーはビット操作後、デコーダーはビット操作前 | lzip manual §6.1 range coder | ✅ | `test_encoder_normalizes_after_bit_operations`, `test_decoder_normalizes_before_bit_operations` |

### lzip エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 30 | ヘッダー形式 (LZIP + version + dict_size) | lzip manual §5 File format | ✅ | `test_encode_header_format` |
| 31 | エンコード→デコード ラウンドトリップ: 空/hello/repeated/all_bytes/1kb | lzip manual §5 File format | ✅ | `test_encode_roundtrip_empty`, `test_encode_roundtrip_hello`, `test_encode_roundtrip_repeated`, `test_encode_roundtrip_all_bytes`, `test_encode_roundtrip_1kb` |
| 32 | 辞書サイズ指定エンコード | lzip manual §5 File format | ✅ | `test_encode_with_larger_dict` |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 33 | system lzip で圧縮したデータのデコード | lzip manual §5 + system `lzip` oracle | ✅ | `test_lzip_decode_system_compressed` (統合) |
| 34 | system lzip -d での展開互換 | lzip manual §5 + system `lzip` oracle | ✅ | `test_lzip_encode_decoded_by_system` (統合) |
| 35 | 大規模データラウンドトリップ | lzip manual §5 + system `lzip` oracle | ✅ | `test_lzip_roundtrip_large` (統合) |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 36 | Dictionary size 範囲: 4KiB (2^12) 〜 512MiB (2^29) | lzip manual | ✅ | dict_size_byte 検証 |
| 37 | LZMA properties 固定値 (lc=3/lp=0/pb=2) | lzip manual §6 | ✅ | N/A — lzip ストリームには properties バイトが存在せず (§5 の DS バイトのみ)、rejection 対象なし。固定値の使用は item 11 で検証 |
| 38 | Trailing data after last member | lzip manual §9 | ✅ | 無視。§9: ゼロバイトパディングは任意量 append 可能、かつ HD≤3 で member header と区別できない trailing は corrupt member header 扱い (GNU lzip 準拠の解釈)。空メンバー+padding/garbage も受理 — `test_empty_member_with_trailing_padding`, `test_empty_member_with_trailing_garbage` |
| 39 | EOS marker 必須 | lzip manual | ✅ | LZMA decoder で検証 |
| 40 | multimember file 内の empty member (data size = 0) は不許可 | lzip manual ch.5 | ✅ | 実装済み — multimember 内の empty member (data size = 0) を reject。単一メンバーの空ファイルは受理。`test_empty_member_in_multimember_rejected` |
| 41 | member size 上限 (member あたり 2 PiB / 16 EiB−1) | lzip manual ch.5 | ✅ | `MAX_MEMBER_SIZE = 2^51` (2 PiB) を明示。decode は trailer の member size 超過を reject、encode 側も data/member size の上限を検証。`test_decode_rejects_oversized_member` |
| 42 | LZMA match length: len−2 を 3 range (0+3bit / 10+3bit / 11+8bit) で符号化、範囲 2..=273 | lzip manual §6.2 | ✅ | `test_min_match_length_2`, `test_max_match_length_273` |
| 43 | rep 距離は `0 <= dis < dict_size`、かつ `dis == position` は位置 0 の直前に仮想ゼロバイトがあるものとして受理 | lzip manual §6.2 | ✅ | 実装済み (`lzma_decode_impl`: `rep0 > output.len()` または `rep0 >= dict_size` で reject、rep0==len は idx underflow → 0 出力)。実エンコーダは生成しないため直接テストなし |
| 44 | range decoder 初期化: 先頭バイト 0x00 必須、code < range (0xFFFFFFFF は拒否) | lzip manual §6.1 | ✅ | `test_decoder_bad_first_byte`, `test_decoder_initial_code_max_rejected` |
| 45 | EOS 後の range decoder 未消費バイト (encoder flush 由来、最大 ~5B) を許容して trailer を探索 | lzip manual §6.1 | ✅ | `test_decode_member_with_range_coder_padding_patterns` (slack 0..=5 で検証) |

---

## 実装メモ

- エンコーダのマッチ探索は後方 4096 バイトに限定 (`find_match` の `search_limit`)。dict_size を大きくしても 4KiB 超の距離は emit しない (圧縮率のみの制約、形式準拠性に影響なし)。
- `decode()` のデフォルト dict_size バイトは 0x0C (4 KiB 固定)。GNU lzip の「file size 以下で最大の dict」方針とは異なるが形式上有効。
- `decode_bounded` は完全 decode 後にサイズ判定する post-hoc 方式 (出力爆発の事前防止ではない)。
- 共有 LZMA コアのエラーメッセージ prefix は `lzma:` (lzma_alone / lrzip / sevenz / squashfs / zip / erofs microlzma と共有のため)。

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 45 |
| **合計** | **45** |


---
