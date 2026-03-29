# RFC 1951 (DEFLATE)

| 項目 | 内容 |
|------|------|
| 仕様メモ | 仕様にテストベクターは含まれず、ハフマン符号構築例 (bit lengths `[3,3,3,3,3,2,4,4]`) が主要な具体例 |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | BTYPE=00 (非圧縮ブロック) デコード | RFC 1951 §3.2.4 | ✅ | `test_decode_uncompressed`, `test_roundtrip_stored` |
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
| 19 | 空入力 | RFC 1951 §3.2 | ✅ | `test_roundtrip_empty`, `test_roundtrip_compressed_empty`, `test_empty_input` |
| 20 | ビット順序: データはLSB-first、ハフマンコードはMSB-first構築 | RFC 1951 §3.1.1 | ✅ | `test_reverse_bits`, Huffman/BitReader 系テスト |
| 21 | ハフマンテーブル構築 (RFC例: bit lengths → codes) | RFC 1951 §3.2.2 | ✅ | `test_huffman_table_build`, `test_huffman_rfc1951_example` |
| 22 | 最大マッチ長 258 | RFC 1951 §3.2.5 | ✅ | `test_encode_length` (258のテストあり) |
| 23 | 最大後方距離 32768 | RFC 1951 §3.2.5 | ✅ | `test_roundtrip_large_distance` |
| 24 | 最大非圧縮ブロック 65535バイト | RFC 1951 §3.2.4 | ✅ | `test_stored_block_max_65535` |
| 25 | 重複コピー (distance < length) | RFC 1951 §3.2.5 | ✅ | `test_fixed_huffman_overlap_copy_direct`, `test_distance_one_self_copy` |
| 26 | エンコード: 非圧縮ブロック (BTYPE=00) | RFC 1951 §3.2.4 | ✅ | `test_roundtrip_stored` |
| 27 | エンコード: 固定ハフマン (BTYPE=01) | RFC 1951 §3.2.6 | ✅ | `test_roundtrip_compressed_short/repetitive` |
| 28 | エンコード: LZ77 ハッシュチェーン圧縮 | RFC 1951 §4 | ✅ | ラウンドトリップテストで検証 |
| 29 | 圧縮率検証 (繰り返しデータが元の50%以下) | RFC 1951 §4 | ✅ | `test_roundtrip_compressed_repetitive` |
| 30 | 後方参照距離超過エラー | RFC 1951 §3.2.5 | ✅ | `test_distance_too_far_back` |
| 31 | 65536バイト → 複数ブロック分割 | RFC 1951 §3.2 | ✅ | `test_stored_block_multi` |
| 32 | LENGTH_BASE/LENGTH_EXTRA RFC 1951 仕様値照合 | RFC 1951 §3.2 | ✅ | `test_length_base_matches_rfc1951` |
| 33 | DISTANCE_BASE/DISTANCE_EXTRA RFC 1951 仕様値照合 | RFC 1951 §3.2 | ✅ | `test_distance_base_matches_rfc1951` |

| 34 | 動的ハフマンの直接デコードテスト | RFC 1951 §3.2.7 | ✅ | `test_dynamic_huffman_direct` (手動構築 BTYPE=10 ブロック) |
| 35 | distance=1 自己参照コピー (RLEパターン) | RFC 1951 §3.2.5 | ✅ | `test_distance_one_self_copy` |
| 36 | 複数ブロック (BFINAL=0→1) | RFC 1951 §3.2.3 | ✅ | `test_multiple_blocks` |
| 37 | コード長リピートの境界テスト | RFC 1951 §3.2.7 | ✅ | `test_code_length_repeat_exact_boundary` |
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
| 51 | Max Huffman code length 15 bits | RFC 1951 §3.2.2 | ✅ | Huffman builder で制限 |
| 52 | Oversubscribed Huffman tree rejection | RFC 1951 §3.2.2 | ✅ | table build で検出 |
| 53 | Distance codes 30-31 は invalid | RFC 1951 §3.2.5 | ✅ | テーブル範囲外 |
| 54 | HLIT range 257-286 validation | RFC 1951 §3.2.7 | ✅ | パーサーで検証 |
| 55 | Byte alignment after BTYPE=00 block | RFC 1951 §3.2.4 | ✅ | decode_uncompressed() |
| 56 | lit/len code 286-287 はデータ中に出現しない (invalid) | RFC 1951 §3.2.6 | ✅ | 固定ハフマンで 286-287 受信時はエラー。decode_huffman_block() の `_ =>` アームで reject |
| 57 | 準拠デコンプレッサーは任意サイズのブロックを受け入れる | RFC 1951 §3.3 | ✅ | ブロックサイズ上限なし (65535 は非圧縮ブロックのみ) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 57 |
| **合計** | **57** |

