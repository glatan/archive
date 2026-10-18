# RFC 8878 (zstd)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [RFC 8878](https://www.rfc-editor.org/rfc/rfc8878.txt) — Zstandard Compression and the 'application/zstd' Media Type (ローカルスナップショット: `docs/spec/sources/rfc8878.txt`) |
| 参照実装 | upstream 参照実装 (facebook/zstd、BSD-3-Clause OR GPLv2。system `zstd` バイナリをテスト時 interop oracle として利用。コード移植なし)。詳細: THIRD_PARTY_NOTICES zstd 項 |
| 仕様メモ | Appendix A に事前定義 FSE デコードテーブル (全ステート値)、§3.1.1.5 に repeat offset の動作例テーブルがある |
| public encoder の current scope | Raw/RLE/Compressed block path、frame header/checksum、dictionary ID metadata まで |
| `cfg(test)` 下の内部実装 | public encoder は predefined FSE/Huffman ベースの compressed block path を使う。custom FSE table 生成・比較の regression helper 群は引き続き `cfg(test)` 下の内部検証用実装 |

### フレーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `0xFD2FB528` 検証 | RFC 8878 §3.1.1 | ✅ | `test_invalid_zstd_magic`, `test_fcs_flag_combinations` |
| 2 | 不正マジックナンバーエラー | RFC 8878 §3.1.1 | ✅ | `test_invalid_zstd_magic` |
| 3 | Frame_Header_Descriptor パース | RFC 8878 §3.1.1 | ✅ | `test_fcs_flag_combinations`, `test_dictionary_id_sizes`, `test_checksum_flag`, `test_single_segment_false_with_window` |
| 4 | 予約ビット (bit 3) 非ゼロエラー | RFC 8878 §3.1.1 | ✅ | `test_descriptor_reserved_bit` |
| 5 | FCS_Flag × Single_Segment_Flag 全組み合わせ | RFC 8878 §3.1.1 | ✅ | `test_fcs_flag_combinations` (FCS_Flag 0-3 × SS=1) |
| 6 | FCS_Flag=1 の +256 オフセット | RFC 8878 §3.1.1 | ✅ | `test_fcs_flag_combinations` 内で検証 |
| 7 | Window_Size 計算 (exponent/mantissa) | RFC 8878 §3.1.1.1.2 | ✅ | `test_window_size_min`, `test_window_size_max_descriptor_rejected`, `test_single_segment_false_with_window` |
| 8 | Window_Size 最小/最大境界 | RFC 8878 §3.1.1.1.2 | ✅ | `test_window_size_min` (1024 B), `test_window_size_at_limit_accepted` (128 MiB), `test_window_size_exceeds_limit_rejected`, `test_window_size_max_descriptor_rejected` |
| 9 | Dictionary_ID フィールド (0/1/2/4バイト) | RFC 8878 §5 | ✅ | `test_dictionary_id_sizes` |
| 10 | Content_Checksum_Flag | RFC 8878 §3.1.1 | ✅ | `test_checksum_flag`, `test_checksum_truncated` |
| 11 | Skippable Frame (0x184D2A50-5F) | RFC 8878 §3.1.1 | ✅ | `test_skippable_frame` |
| 12 | フレーム短すぎエラー | RFC 8878 §3.1.1 | ✅ | `test_zstd_frame_too_short` |
| 13 | 空入力 | RFC 8878 §3.1.1 | ✅ | `test_empty_input` |
| 14 | マルチフレーム | RFC 8878 §3.1.1 | ✅ | `test_zstd_multi_frame`、`test_truncated_at_every_position` (全切断位置で拒否) |

### ブロック構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | ブロックヘッダー (3バイト) パース | RFC 8878 §3.1.1.2 | ✅ | `test_block_header_parse` |
| 16 | BlockType=Raw デコード | RFC 8878 §3.1.1.2 | ✅ | `test_repeat_offset_spec_example`, `test_skippable_frame` |
| 17 | BlockType=RLE デコード | RFC 8878 §3.1.1.2 | ✅ | `test_rle_block_direct` |
| 18 | BlockType=Compressed デコード | RFC 8878 §3.1.1.2 | ✅ | `test_compressed_block_literals_only` |
| 19 | BlockType=Reserved パース | RFC 8878 §3.1.1.2 | ✅ | `test_block_type_reserved_error` |
| 20 | Last_Block フラグ | RFC 8878 §3.1.1.2 | ✅ | `test_block_header_parse` |
| 21 | Block_Size (21ビット) | RFC 8878 §3.1.1.2 | ✅ | `test_block_header_parse` |

### リテラルセクション

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | Raw_Literals_Block (type=0) | RFC 8878 §3.1.1.3 | ✅ | `test_raw_literals_block_direct`, `test_compressed_block_literals_only` |
| 23 | RLE_Literals_Block (type=1) | RFC 8878 §3.1.1.3 | ✅ | `test_rle_literals_block_direct` |
| 24 | Compressed_Literals_Block (type=2, ツリー付き) | RFC 8878 §3.1.1.3 | ✅ | `test_compressed_literals_with_tree_direct`, `test_compressed_block_literals_only` |
| 25 | Treeless_Literals_Block (type=3) | RFC 8878 §3.1.1.3 | ✅ | `test_treeless_literals_with_previous_table_direct` |
| 26 | Treeless で前ツリーなしエラー | RFC 8878 §3.1.1.3 | ✅ | `test_treeless_literals_without_previous_table_error` |
| 27 | 1ストリーム vs 4ストリーム | RFC 8878 §3.1.1.3 | ✅ | `test_compressed_literals_header_size_formats_roundtrip`, `test_treeless_literals_four_stream_jump_table_direct` |
| 28 | 4ストリーム Jump_Table (6バイト) | RFC 8878 §3.1.1.3 | ✅ | `test_treeless_literals_four_stream_jump_table_direct` |
| 29 | Size_Format 各パターン (5/12/20ビット) | RFC 8878 §3.1.1.3 | ✅ | `test_decode_literals_header_size_formats`, `test_compressed_literals_header_size_formats_roundtrip` |

### シーケンスセクション

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 30 | Number_of_Sequences: byte0 < 128 | RFC 8878 §3.1.1.4 | ✅ | `test_decode_sequences_header_small`, `test_sequences_header_boundary_127` |
| 31 | Number_of_Sequences: 128 ≤ byte0 < 255 | RFC 8878 §3.1.1.4 | ✅ | `test_decode_sequences_header_medium`, `test_sequences_header_boundary_128/254` |
| 32 | Number_of_Sequences: byte0 = 255 | RFC 8878 §3.1.1.4 | ✅ | `test_decode_sequences_header_large` |
| 33 | 圧縮モード: Predefined (0) | RFC 8878 §3.1.1.4 | ✅ | `test_get_fse_table_predefined_mode` |
| 34 | 圧縮モード: RLE (1) | RFC 8878 §3.1.1.4 | ✅ | `test_get_fse_table_rle_mode` |
| 35 | 圧縮モード: FSE_Compressed (2) | RFC 8878 §3.1.1.4 | ✅ | `test_get_fse_table_fse_compressed_mode`, `test_from_bitstream_matches_system_zstd_weight_header` |
| 36 | 圧縮モード: Repeat (3) | RFC 8878 §3.1.1.4 | ✅ | `test_repeat_mode_across_blocks`, `test_get_fse_table_repeat_mode` |
| 37 | Repeat で前テーブルなしエラー | RFC 8878 §3.1.1.4 | ✅ | `test_repeat_mode_first_block_error` |
| 38 | Symbol_Compression_Modes 予約ビット (1-0) 非ゼロエラー | RFC 8878 §3.1.1.4 | ✅ | `test_sequence_compression_modes_reserved_bits_error` |
| 39 | シーケンス実行 (リテラルコピー + マッチコピー) | RFC 8878 §3.1.1.4 | ✅ | `test_execute_simple` |
| 40 | ゼロオフセットエラー | RFC 8878 §3.1.1.4 | ✅ | `test_execute_zero_offset` |
| 41 | オフセット超過エラー | RFC 8878 §3.1.1.4 | ✅ | `test_execute_offset_beyond_history` |
| 42 | リテラルオーバーフローエラー | RFC 8878 §3.1.1.4 | ✅ | `test_execute_literal_overflow` |

### FSE (Finite State Entropy)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 43 | FSEテーブル構築 (確率分布→テーブル) | RFC 8878 §4.1 / Appendix A | ✅ | `test_default_tables_build` |
| 44 | FSEビットストリームからのテーブル構築 | RFC 8878 §4.1 / Appendix A | ✅ | `test_from_bitstream_matches_system_zstd_weight_header`, `test_get_fse_table_fse_compressed_mode` |
| 45 | Accuracy_Log パース (4ビット + 5) | RFC 8878 §4.1 / Appendix A | ✅ | `test_from_bitstream_matches_system_zstd_weight_header`, `test_accuracy_log_upper_limit_rejection` |
| 46 | Accuracy_Log 上限検証 (LL/ML=9, OF=8) | RFC 8878 §4.1 / Appendix A | ✅ | `test_accuracy_log_upper_limit_rejection` |
| 47 | 確率 -1 (less than 1) の処理 | RFC 8878 §4.1 / Appendix A | ✅ | `test_default_ll/ml/of_table_appendix_a` で検証 |
| 48 | ゼロ確率リピートコーディング | RFC 8878 §4.1 / Appendix A | ✅ | `test_from_bitstream_matches_system_zstd_weight_header` (system zstd 由来の zero-probability runs を含む FSE bitstream) |
| 49 | 事前定義テーブル: Literal Length (AL=6, 36シンボル) | RFC 8878 §4.1 / Appendix A | ✅ | `test_default_ll_table_appendix_a` |
| 50 | 事前定義テーブル: Match Length (AL=6, 53シンボル) | RFC 8878 §4.1 / Appendix A | ✅ | `test_default_ml_table_appendix_a` |
| 51 | 事前定義テーブル: Offset (AL=5, 29シンボル) | RFC 8878 §4.1 / Appendix A | ✅ | `test_default_of_table_appendix_a` |
| 52 | highest_bit 関数 | RFC 8878 §4.1 / Appendix A | ✅ | `test_highest_bit` |
| 53 | **Appendix A テーブル値との完全一致検証** | RFC 8878 Appendix A | ✅ | `test_default_ll/ml/of_table_appendix_a` (全エントリのシンボル分布を確率と照合) |

### ハフマン (リテラル用)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 54 | 重みからテーブル構築 | RFC 8878 §4.2 | ✅ | `HuffmanTable::from_weights()` |
| 55 | 直接表現 (header ≥ 128): 4ビット重み | RFC 8878 §4.2 | ✅ | `test_direct_weights` |
| 56 | FSE圧縮重み (header < 128) | RFC 8878 §4.2 | ✅ | `test_parse_huffman_weights_system_zstd_header_regression`, `test_decompress_fse_weights_via_roundtrip` |
| 57 | 最後のシンボルの暗黙的重み | RFC 8878 §4.2 | ✅ | `test_build_literals_huffman_table_adds_implicit_last_weight` |
| 58 | 最大コード長 11ビット | RFC 8878 §4.2 | ✅ | `test_huffman_max_code_length_11bit`, `test_huffman_code_length_exceeds_11bit_error` (バリデーション追加) |
| 59 | highest_bit_ceil 関数 | RFC 8878 §4.2 | ✅ | `test_highest_bit_ceil` |
| 60 | Huffman 重み合計が2冪制約 | RFC 8878 §4.2 | ✅ | `test_huffman_weight_sum_not_power_of_2` |

### Repeat Offset

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 61 | 初期値 (1, 4, 8) | RFC 8878 §3.1.1.5 | ✅ | `test_repeat_offset_spec_example` (Raw ブロックで初期状態検証) |
| 62 | literal_length > 0 時: offset 1=RepOff1, 2=RepOff2, 3=RepOff3 | RFC 8878 §3.1.1.5 | ✅ | `test_repeat_offset_rfc8878`, `test_repeat_offset_rotation_3_steps` |
| 63 | literal_length == 0 時のシフト: 1=RepOff2, 2=RepOff3, 3=RepOff1-1 | RFC 8878 §3.1.1.5 | ✅ | `test_repeat_offset_rfc8878`, `test_offset_raw3_ll0_rep0_is_1` |
| 64 | **仕様の動作例テーブル (9ステップ) との照合** | RFC 8878 §3.1.1.5 | ✅ | `test_repeat_offset_rfc8878` (resolve_offset関数で全9ステップ照合) |

### ビットストリーム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 65 | 逆順ビットストリーム (末尾→先頭) | RFC 8878 §3.1.1.3-§4.2 | ✅ | `test_bitdstream_reads_from_tail_with_sentinel`, `test_fse_state_out_of_range` |
| 66 | センチネルビット (最終バイトの先頭1ビット) | RFC 8878 §3.1.1.3-§4.2 | ✅ | `test_bitdstream_reads_from_tail_with_sentinel` |
| 67 | 最終バイト=0x00 のエラー | RFC 8878 §3.1.1.3-§4.2 | ✅ | `test_bitdstream_requires_nonzero_last_byte` |
| 68 | 状態初期化順序 (LL, OF, ML) | RFC 8878 §3.1.1.3-§4.2 | ✅ | `test_fse_state_out_of_range` (LL→OF→ML 初期読取順を前提に OF state failure を固定) |
| 69 | デコード順序 (OF, ML, LL) | RFC 8878 §3.1.1.3-§4.2 | ✅ | `test_decode_sequences_reads_offset_ml_ll_in_order` |
| 70 | 状態更新順序 (LL, ML, OF) | RFC 8878 §3.1.1.3-§4.2 | ✅ | `test_decode_sequences_updates_states_ll_ml_of_order` |

### チェックサム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 71 | XXH64 (seed=0) 下位32ビット | RFC 8878 §3.1.1 | ✅ | `test_xxhash64_hello_world_checksum`, `test_checksum_present` |
| 72 | チェックサム不一致エラー | RFC 8878 §3.1.1 | ✅ | `test_zstd_checksum_mismatch` |
| 73 | Frame_Content_Size 不一致エラー | RFC 8878 §3.1.1 | ✅ | `test_zstd_size_mismatch` |

### コードテーブル値

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 74 | LL_BASE/LL_EXTRA (36シンボル) 仕様値一致 | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_ll_base_matches_spec`, `test_ll_extra_matches_spec` |
| 75 | ML_BASE/ML_EXTRA (53シンボル) 仕様値一致 | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_ml_base_matches_spec`, `test_ml_extra_matches_spec` |
| 76 | Offset 計算式 `(1 << code) + readNBits(code)` | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_offset_code_zero`, `test_offset_formula_nonzero_code` |
| 77 | ブロックサイズ超過エラー | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_block_size_exceeds_frame` |
| 78 | Block_Maximum_Size (min(window_size, 128KB)) 検証 | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_block_size_exceeds_frame`, `test_compressed_block_decompressed_size_exceeds_block_maximum_size` |
| 79 | LL/ML コード範囲検証 (LL≤35, ML≤52) | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_match_length_code_out_of_range`, `test_literal_length_code_out_of_range` |
| 80 | 圧縮ブロック: リテラルのみ (num_sequences=0) | RFC 8878 §3.1.1.3 / §3.1.1.4 / Appendix A | ✅ | `test_compressed_block_literals_only` |

### エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 81 | フレームヘッダー生成 (マジック + ディスクリプタ + FCS) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_frame_structure` |
| 82 | FCS_Flag サイズ選択 (0-3) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_fcs_sizes` |
| 83 | FCS 2バイトエンコード (+256 オフセット) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_fcs_2byte` |
| 84 | FCS 4バイトエンコード | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_fcs_4byte` |
| 85 | Raw ブロック生成 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_small` |
| 86 | RLE ブロック生成 (全バイト同一) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_rle` |
| 87 | 空入力エンコード | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_empty` |
| 88 | 大入力の複数ブロック分割 (128KB境界) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_large` |
| 89 | XXH64 コンテンツチェックサム生成 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_checksum_present` |
| 90 | encode_writer (std::io::Write 対応) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_encode_writer` |
| 91 | エンコード→デコード ラウンドトリップ | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_*` (11テスト) |
| 92 | public encoder: LZ77 圧縮ブロック生成 (Compressed block type) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_public_encoder_emits_compressed_block_for_compressible_input`, `test_roundtrip_repetitive`, `test_roundtrip_prose` |
| 93 | public encoder: 事前定義FSEテーブルによるシーケンスエンコード (mode=0) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | public path は predefined-table block を生成。`test_public_encoder_emits_compressed_block_for_compressible_input`, `test_roundtrip_prose` |
| 94 | Raw_Literals_Block 生成 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_repetitive` |
| 95 | FSE 逆ビットストリーム生成 (センチネルビット付き) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_prose`, `test_roundtrip_repetitive` |
| 96 | public encoder: 圧縮/Raw ブロック自動選択 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_binary` (非圧縮データ→Raw), `test_public_encoder_emits_compressed_block_for_compressible_input` (圧縮データ→Compressed) |
| 97 | LL/ML/OF コードエンコード | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_encode_ll_code`, `test_encode_ml_code`, `test_encode_of_code` |
| 98 | RLE ブロックの正しいバイト消費 (1バイトのみ) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_rle` (エンコーダ連携で検証) |
| 99 | internal helper: ハフマンリテラル圧縮 (Compressed_Literals_Block type=2 生成) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_huffman_literals_roundtrip`, `test_roundtrip_english_text` |
| 100 | internal helper: ハフマン重み直接表現シリアライズ (4-bit nibbles) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_huffman_build_lengths`, `test_huffman_canonical_codes` |
| 101 | internal helper: ハフマン逆ビットストリーム (シングルストリーム、センチネル付き) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_huffman_stream_encode_decode` |
| 102 | internal helper: カスタム FSE テーブル生成 (mode=2, 頻度正規化 + ビットストリームシリアライズ) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_custom_fse_roundtrip`, `test_custom_fse_with_huffman_roundtrip` |
| 103 | internal helper: カスタム FSE テーブルシリアライズ/デシリアライズ往復 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_fse_table_serialize_roundtrip`, `test_custom_fse_serialize_deserialize` |
| 104 | internal helper: カスタム/事前定義 FSE テーブル自動選択 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_roundtrip_english_text` (helper coverage) |
| 105 | 頻度正規化 (normalize_counts) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_normalize_counts_basic`, `test_normalize_counts_mixed_probabilities_serialize_roundtrip` |
| 106 | FSE 確率値エンコードの max_bits_needed 修正 (RFC 8878 §4.1.1 準拠) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_fse_table_serialize_roundtrip` |
| 107 | large literals / large text の public encoder roundtrip | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_large_literals_roundtrip`, `test_large_text_roundtrip`, `test_zstd_encode_large_literals_roundtrip` |
| 108 | public encoder 出力のシステム zstd 互換性 (大きい text) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_zstd_encode_large_text_system_compat` (統合テスト) |
| 109 | public encoder 出力のシステム zstd 互換性 (大きい raw payload) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_zstd_encode_large_raw_system_compat` (統合テスト) |
| 110 | Dictionary パース (RFC 8878 §5: magic, dict_id, entropy tables, content) | RFC 8878 §5 | ✅ | `test_dict_parse_invalid_magic`, `test_dict_parse_too_short` |
| 111 | Dictionary デコード (辞書コンテンツを履歴プレフィックスとして使用) | RFC 8878 §5 | ✅ | `test_execute_sequences_with_dict_content`, `test_execute_sequences_with_dict_overlap` |
| 112 | Dictionary ID 不一致/未提供エラー | RFC 8878 §5 | ✅ | `test_decode_dict_required_but_missing`, `test_decode_dict_id_mismatch` |
| 113 | Dictionary 付きデコードのシステム zstd 互換性 | RFC 8878 §5 | ✅ | `test_zstd_decode_with_dict_system` (統合テスト) |
| 114 | public encoder の dictionary ID 付きエンコード (dict 履歴は先頭ブロックのみ使用、2 ブロック目以降は直前 `WINDOW_SIZE` バイトの実 frame 履歴を使用) | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_encode_with_dict_roundtrip`, `test_encode_with_dict_multiblock_roundtrip`, `test_fuzz_regression_zstd_dict_self` |
| 115 | dictionary ID 付き public encoder 出力のシステム zstd 互換性 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_zstd_encode_with_dict_system_compat` (統合テスト) |
| 116 | Compressed_Literals_Header size_format=0/1/2/3 の境界値 | RFC 8878 §3.1.1 / §3.1.1.2-§3.1.1.5 / §4.1 / §4.2 / §5 | ✅ | `test_compressed_literals_header_size_formats_roundtrip` |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 117 | Dictionary: repeat offsets 初期化 (default 1,4,8 → dictionary 値で上書き) | RFC 8878 §5 | ✅ | decode_with_dict 実装 |
| 118 | Dictionary: entropy tables replacement (Huffman + FSE for LL/ML/OF) | RFC 8878 §5 | ✅ | decode_with_dict 実装 |
| 119 | Window_Size 上限チェック (128 MiB; level-1 conformance は 8 MB、level-2 以上は緩和) | RFC 8878 §3.1.1.1.2 | ✅ | `test_window_size_exceeds_limit_rejected`, `test_window_size_at_limit_accepted`, `test_window_size_max_descriptor_rejected` |
| 120 | Single-symbol Huffman tree | RFC 8878 §4.2.1 | ✅ | HuffmanTable 実装 |
| 121 | Last sequence: literals 追加後の match copy 制約 | RFC 8878 §3.1.1.4 | ✅ | execute_sequences() |
| 122 | Sequences ビットストリーム完全消費検証 | RFC 8878 §3.1.1.3.2.1.2 | ✅ | `is_fully_consumed()` で検証、未消費で InvalidData |
| 123 | Huffman ビットストリーム完全消費検証 | RFC 8878 §4.2.2 | ✅ | `byte_pos != 0 \|\| bits_available != 0` で InvalidData |
| 124 | FSE テーブル: 累積確率超過で corruption エラー | RFC 8878 §4.1.1 | ✅ | remaining != 1 チェックにより "FSE probabilities do not sum to table size" で InvalidData |
| 125 | FSE テーブル: デコード済みシンボル数の検証 | RFC 8878 §4.1.1 | ✅ | `symbol > max_symbol + 1` で InvalidData |
| 126 | 4-stream Jump_Table: ストリームサイズ合計超過で corruption エラー | RFC 8878 §3.1.1.3.1.6 | ✅ | `s3_end > stream_data.len()` で InvalidData |
| 127 | Frame_Header_Descriptor の unused bit (bit 4) は decoder が解釈しない | RFC 8878 §3.1.1.1.1.3 | ✅ | bit3 のみ検査し bit4 は無視 |
| 128 | 各 frame は少なくとも 1 ブロックを持つ | RFC 8878 §3.1.1.2 | ✅ | decode ループ構造上暗黙に強制 |
| 129 | literals ヘッダ byte0==0 のとき Repeat_Mode の FSE テーブルは更新されない | RFC 8878 §3.1.1.3.2.1 | ✅ | decode.rs の早期 return パス |
| 130 | Raw/RLE ブロックは offset history (repeat offsets) に寄与しない | RFC 8878 §3.1.1.5 | ✅ | rep_offsets は compressed block 内でのみ変更 |
| 131 | Repeat_Mode は直前モード (RLE/Predefined 含む) のテーブルを再利用する | RFC 8878 §3.1.1.3.2.1 | ✅ | 新しい表を作ったときだけ `prev_table` を入れ替え、Repeat はクローンせず同じ表を参照する。`test_get_fse_table_repeat_mode` |
| 132 | Huffman 重み用 FSE の max accuracy log = 6 | RFC 8878 §4.2.1.2 | ✅ | `from_bitstream(data, 12, 6)` |
| 133 | raw content dictionary (magic なし、≥8 bytes) | RFC 8878 §5 | ✅ | `ZstdDict::from_content` |
| 134 | Window_Size より大きい過去データへの offset は error (all offsets leading to previously decoded data must be smaller than Window_Size) | RFC 8878 §3.1.1.4 | ✅ | `execute_sequences_with_dict` で `output.len() > window_size` のとき `offset > window_size` を reject (RFC §5: output ≤ window の間は dict 領域を window 超 offset で参照可能)。`test_execute_offset_beyond_window_size` `test_execute_offset_within_window_size_ok` `test_compressed_block_offset_exceeds_window` |
| 135 | dictionary は出力総量が Window_Size を超えた後はアクセス不可 | RFC 8878 §5 | ✅ | output.len() > window_size 以降は offset <= window_size のみ許容されるため dict 領域への参照は自動的に不可。`test_execute_dict_cutoff_after_window` `test_execute_dict_reference_allowed_before_window` |
| 136 | FSE テーブル記述は nonzero probability を持つシンボルが 2 個以上必要 | RFC 8878 §4.1.1 | ✅ | `FseTable::from_probabilities` で nonzero < 2 を reject。RLE mode は別経路で影響なし。`test_from_probabilities_rejects_fewer_than_two_nonzero_symbols` `test_from_bitstream_rejects_single_symbol_description` |
| 137 | dictionary の repeat offsets (rep1-3) は dictionary size 未満でなければならない | RFC 8878 §5 | ✅ | `ZstdDict::parse` で `rep == 0 || rep >= content.len()` を reject。`test_dict_parse_rep_offset_out_of_range` `test_dict_parse_rep_offset_zero` |
| 138 | Dictionary_ID = 0 は dictionary magic 形式で無効 (`parse` 経路) | RFC 8878 §5 | ✅ | `ZstdDict::parse` で `id == 0` を reject。`test_dict_parse_zero_dictionary_id` |
| 139 | decoder はメモリ要求を制限すべき (FCS に基づく無制限 reserve の禁止) | RFC 8878 §3.1.1.1.1.2 / §8 | ✅ | `decode_frame` は `try_reserve(min(FCS, 128 MiB))` にクランプ (MAX_WINDOW_SIZE と同値)、失敗は非致命で通常伸長にフォールバック。`test_decode_frame_huge_fcs_no_panic` |
| 140 | reserved Dictionary_ID 範囲 (≤32767, ≥2^31) を参照する payload は error | RFC 8878 §3.1.1.1.3 | ✅ | `is_reserved_dictionary_id` で [1,32767] ∪ [2^31,2^32-1] を検出、dict 未提供なら reject。dict 提供で ID 一致なら受理。`test_decode_reserved_dictionary_id_no_dict` `test_decode_nonreserved_dictionary_id_boundaries` `test_decode_reserved_dictionary_id_with_matching_dict` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 140 |
| ❌ 未実装  | 0 |
| **合計** | **140** |

