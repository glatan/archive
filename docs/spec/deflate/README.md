# RFC 1951 (DEFLATE)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951.txt) — DEFLATE Compressed Data Format Specification version 1.3 (ローカルスナップショット: `docs/spec/sources/rfc1951.txt`) |
| 参照実装 | zlib (zlib license、`inflate_table`/`gen_bitlen` の動作参照)。詳細: THIRD_PARTY_NOTICES DEFLATE 項 |
| 仕様メモ | 仕様にテストベクターは含まれず、ハフマン符号構築例 (bit lengths `[3,3,3,3,3,2,4,4]`) が主要な具体例 |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | BTYPE=00 (非圧縮ブロック) デコード | RFC 1951 §3.2.4 | ✅ | `test_decode_uncompressed`、`test_roundtrip_stored`、`test_stored_block_zero_len` (LEN=0) |
| 2 | BTYPE=00 LEN/NLEN 一致検証 | RFC 1951 §3.2.4 | ✅ | `decode_uncompressed()` 内で検証 |
| 3 | BTYPE=00 LEN/NLEN 不一致エラー | RFC 1951 §3.2.4 | ✅ | `test_stored_len_nlen_mismatch` |
| 4 | BTYPE=01 (固定ハフマン) デコード | RFC 1951 §3.2.6 | ✅ | `test_fixed_huffman_direct`, `test_roundtrip_compressed_short` |
| 5 | BTYPE=10 (動的ハフマン) デコード | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct`, `test_dynamic_huffman_direct_uses_repeat17`, `test_dynamic_huffman_direct_uses_repeat16` |
| 6 | BTYPE=11 (予約) エラー | RFC 1951 §3.2.3 | ✅ | `test_invalid_btype_11` |
| 7 | 固定ハフマンコード長テーブル (0-143: 8bit, 144-255: 9bit, 256-279: 7bit, 280-287: 8bit) | RFC 1951 §3.2.6 | ✅ | `test_fixed_huffman_lengths` |
| 8 | 固定距離コード (5bit, 0-31) | RFC 1951 §3.2.5 | ✅ | `test_distance_base_matches_rfc1951`, `test_encode_distance_all_code_boundaries` |
| 9 | 長さコード (257-285) + 追加ビット | RFC 1951 §3.2.5 | ✅ | `test_encode_length`, `test_length_base_matches_rfc1951` |
| 10 | 距離コード (0-29) + 追加ビット | RFC 1951 §3.2.5 | ✅ | `test_encode_distance`, `test_distance_base_matches_rfc1951` |
| 11 | 動的ハフマン: HLIT, HDIST, HCLEN パース | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct`, 統合テスト |
| 12 | 動的ハフマン: コード長アルファベット (0-18) | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct`, 統合テスト |
| 13 | 動的ハフマン: リピートコード 16 (直前を3-6回) | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct_uses_repeat16`, `test_code_length_repeat16_no_previous` |
| 14 | 動的ハフマン: リピートコード 17 (0を3-10回) | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct_uses_repeat17` |
| 15 | 動的ハフマン: リピートコード 18 (0を11-138回) | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct`, `test_code_length_repeat_overflow` |
| 16 | 動的ハフマン: コード長パーミュテーション順序 | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct`, `test_dynamic_huffman_direct_uses_repeat17`, `test_dynamic_huffman_direct_uses_repeat16` |
| 17 | ブロック跨ぎの後方参照 | RFC 1951 §3.2.5 | ✅ | `test_cross_block_back_reference_direct` |
| 18 | 終端記号 (256) | RFC 1951 §3.2.5 | ✅ | `test_fixed_huffman_direct`, `test_dynamic_huffman_direct` |
| 19 | 空入力 | RFC 1951 §3.2 | ✅ | `test_roundtrip_empty`、`test_roundtrip_compressed_empty`、`test_empty_input`、`test_truncated_at_every_position` (全切断位置で拒否) |
| 20 | ビット順序: データはLSB-first、ハフマンコードはMSB-first構築 | RFC 1951 §3.1.1 | ✅ | `test_reverse_bits`, Huffman/BitReader 系テスト |
| 21 | ハフマンテーブル構築 (RFC例: bit lengths → codes) | RFC 1951 §3.2.2 | ✅ | `test_huffman_table_build`, `test_huffman_rfc1951_example` |
| 22 | 最大マッチ長 258 | RFC 1951 §3.2.5 | ✅ | `test_encode_length` (258のテストあり) |
| 23 | 最大後方距離 32768 | RFC 1951 §3.2.5 | ✅ | 境界自体は `test_encode_distance_boundaries` (32768→code 29) で直接検証。`test_roundtrip_large_distance`, `test_distance_max_32768` は大距離間隔を持つ入力の roundtrip |
| 24 | 最大非圧縮ブロック 65535バイト | RFC 1951 §3.2.4 | ✅ | `test_stored_block_max_65535` |
| 25 | 重複コピー (distance < length) | RFC 1951 §3.2.5 | ✅ | `test_fixed_huffman_overlap_copy_direct`, `test_distance_one_self_copy` |
| 26 | エンコード: 非圧縮ブロック (BTYPE=00) | RFC 1951 §3.2.4 | ✅ | `test_roundtrip_stored` |
| 27 | エンコード: 固定ハフマン (BTYPE=01) | RFC 1951 §3.2.6 | ✅ | `test_roundtrip_compressed_short/repetitive`。LZ77 経路は非圧縮入力 32KiB ごとにブロックを分け、BFINAL は最終ブロックだけ (`test_lz77_blocks_roundtrip`) |
| 28 | エンコード: LZ77 ハッシュチェーン圧縮 | RFC 1951 §4 | ✅ | ラウンドトリップテストで検証。一致長は `match_ops::match_len` |
| 29 | 圧縮率検証 (繰り返しデータが元の50%以下) | RFC 1951 §4 | ✅ | `test_roundtrip_compressed_repetitive` |
| 30 | 後方参照距離超過エラー | RFC 1951 §3.2.5 | ✅ | `test_distance_too_far_back` |
| 31 | 65536バイト → 複数ブロック分割 | RFC 1951 §3.2 | ✅ | `test_stored_block_multi` |
| 32 | LENGTH_BASE/LENGTH_EXTRA RFC 1951 仕様値照合 | RFC 1951 §3.2 | ✅ | `test_length_base_matches_rfc1951` |
| 33 | DISTANCE_BASE/DISTANCE_EXTRA RFC 1951 仕様値照合 | RFC 1951 §3.2 | ✅ | `test_distance_base_matches_rfc1951` |
| 34 | 動的ハフマンの直接デコードテスト | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct` (手動構築 BTYPE=10 ブロック) |
| 35 | distance=1 自己参照コピー (RLEパターン) | RFC 1951 §3.2.5 | ✅ | `test_distance_one_self_copy` |
| 36 | 複数ブロック (BFINAL=0→1) | RFC 1951 §3.2.3 | ✅ | `test_multiple_blocks`、`test_fixed_then_stored_block_alignment` (混合 BTYPE) |
| 37 | コード長リピートの境界テスト | RFC 1951 §3.2.7 | ✅ | `test_code_length_repeat_overflow`, `test_code_length_repeat16_no_previous`。`test_code_length_repeat_exact_boundary` は roundtrip のみ (テストコメントも同旨) |
| 38 | encode_length 境界値 (3, 10, 258) | RFC 1951 §3.2.5 | ✅ | `test_encode_length_boundaries` |
| 39 | encode_distance 境界値 (1, 32768) | RFC 1951 §3.2.5 | ✅ | `test_encode_distance_boundaries` |
| 40 | encode_length(0) パニック | RFC 1951 §3.2.5 | ✅ | `test_encode_length_zero_panics` |
| 41 | encode_distance(0) パニック | RFC 1951 §3.2.5 | ✅ | `test_encode_distance_zero_panics` |
| 42 | エンコード: 動的ハフマン (BTYPE=10) | RFC 1951 §3.2.7 / §4 | ✅ | `test_dynamic_huffman_roundtrip`, `test_dynamic_huffman_english_text` |
| 43 | 動的ハフマン: 全バイト値入力 | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_all_byte_values` |
| 44 | 動的ハフマン vs 固定ハフマン圧縮率 | RFC 1951 §3.2.6 / §3.2.7 / §4 | ✅ | `test_dynamic_vs_fixed_compression_ratio` |
| 45 | 動的ハフマン: コード長構築 (1シンボル) | RFC 1951 §3.2.7 | ✅ | `test_build_code_lengths_single_symbol` |
| 46 | 動的ハフマン: コード長構築 (2シンボル) | RFC 1951 §3.2.7 | ✅ | `test_build_code_lengths_two_symbols` |
| 47 | 動的ハフマン: カノニカルコード生成 | RFC 1951 §3.2.2 / §3.2.7 | ✅ | `test_build_canonical_codes` |
| 48 | 動的ハフマン: RLE コード長エンコード | RFC 1951 §3.2.7 | ✅ | `test_rle_encode_code_lengths` |
| 49 | 動的ハフマン: RLE 長ゼロラン (コード18) | RFC 1951 §3.2.7 | ✅ | `test_rle_encode_long_zero_run` |
| 50 | 最大マッチ長 258 エンコード | RFC 1951 §3.2.5 | ✅ | `test_max_match_length_258` |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 51 | Max Huffman code length 15 bits。エンコーダは kraft_limit で over-subscription を修復し complete code (Σ2^-len = 1) を emit。ただし全 literal 時は §3.2.7 許容の特例として `dist_lengths[0]=1` の単一コード (incomplete, Kraft=1/2) を emit する | RFC 1951 §3.2.2 / §3.2.7 | ✅ | `test_deflate_complete_dist_tree`, `test_build_code_lengths_over_subscribed_complete` |
| 52 | Oversubscribed Huffman tree rejection | RFC 1951 §3.2.2 | ✅ | `HuffmanTable::from_lengths` で Kraft 剰余追跡 (zlib inflate 方式) により over-subscribed 木を reject。incomplete (under-subscribed) 木・空 dist テーブル・1 シンボル dist は lit/len・CL・dist のいずれの木でも従来通り受理 (zlib `inflate_table` は lit/len・CL 木の incomplete を reject するため本実装の方が寛容)。`test_huffman_table_oversubscribed` `test_oversubscribed_huffman_rejected` `test_oversubscribed_dist_tree_rejected` `test_oversubscribed_code_length_code_rejected` |
| 53 | Distance codes 30-31 は invalid | RFC 1951 §3.2.5 | ✅ | テーブル範囲外 |
| 54 | HLIT range 257-286 validation | RFC 1951 §3.2.7 | ✅ | `test_hlit_exceeds_max` (287 拒否)、`test_dynamic_huffman_hlit_max_286_accepted` (286 受理) |
| 55 | Byte alignment after BTYPE=00 block | RFC 1951 §3.2.4 | ✅ | `test_decode_uncompressed`、`test_fixed_then_stored_block_alignment` (Huffman ブロック後の再整列) |
| 56 | lit/len code 286-287 はデータ中に出現しない (invalid) | RFC 1951 §3.2.6 | ✅ | 固定ハフマンで 286-287 受信時はエラー。decode_huffman_block() の `_ =>` アームで reject |
| 57 | 準拠デコンプレッサーは任意サイズのブロックを受け入れる | RFC 1951 §3.3 | ✅ | ブロックサイズ上限なし (65535 は非圧縮ブロックのみ) |
| 58 | 距離コードの特別規則: 距離コード 0 個 (コード長全ゼロ) は all-literals ストリームとして受理。距離コード 1 個のみの場合は 0bit ではなく 1bit で符号化し、残りは未使用コード | RFC 1951 §3.2.7 | ✅ | `HuffmanTable::from_lengths` は全ゼロ距離長を空テーブルとして受理 (距離コード使用時のみ `empty Huffman table` で拒否)。`test_dynamic_huffman_all_literals_empty_dist_tree`, `test_dynamic_huffman_empty_dist_tree_rejects_match`, `test_encode_dynamic_all_literals_roundtrip`, `test_dynamic_huffman_direct` 系 |
| 59 | コード長リピートコード (16/17/18) は HLIT+257 → HDIST+1 の境界をまたいで適用される。全コード長は HLIT+HDIST+258 要素の単一シーケンス | RFC 1951 §3.2.7 | ✅ | `decode_dynamic_huffman` は lit/dist を単一 `lengths` バッファとして処理。`test_dynamic_huffman_repeat16_spans_lit_dist_boundary` |
| 60 | マルチバイト整数は LSB-first (little-endian) で格納される (LEN/NLEN 等) | RFC 1951 §3.1 | ✅ | `read_u16_le` 等 |
| 61 | HDIST=31/32 の受理 (dist code 30/31 のコード長が 0 なら RFC 上は合法) | RFC 1951 §3.2.7 / §3.3 | ✅ | 予約された距離コード 30/31 のコード長が非ゼロであれば拒否し、コード長 0 であれば受理する。`test_dynamic_huffman_hdist_31_zero_lengths_accepted`, `test_dynamic_huffman_hdist_32_zero_lengths_accepted`, `test_dynamic_huffman_hdist_31_nonzero_reserved_length_rejected` |
| 62 | 動的ブロックで lit/len symbol 256 (EOB) のコード長が 0 → reject | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_missing_eob` |
| 63 | プリセット辞書 (`decode_with_dict` / `encode_with_dict`) | RFC 1951 §3.2.3 注記 | ✅ | zlib 層および mscab から利用。往復・誤辞書 reject は zlib 層テスト (`test_decode_with_dict_roundtrip`, `test_decode_with_dict_wrong_dict_rejected`) で検証 |
| 64 | ストリーム終端の lenient 受理: BitReader は末尾の不足ビットをゼロ埋め、BFINAL ブロック後の末尾ゴミバイトは無検証で無視 | RFC 1951 §3.2.3 (実装上の寛容差分) | ✅ | 厳格な実装より寛容 (zlib 同様)。`test_trailing_garbage_after_final_block_ignored`、`test_peek_bits_zero_padded_at_eof` (util/bitreader)。部分読み `decode_stream`・出力上限 `decode_bounded`・`encode_max_match` は内部利用向け API |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 64 |
| ⚠️ 部分実装  | 0 |
| ❌ 未実装  | 0 |
| **合計** | **64** |

