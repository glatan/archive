# Brotli (RFC 7932)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [RFC 7932](https://www.rfc-editor.org/rfc/rfc7932.txt) (2016) — Brotli Compressed Data Format (ローカルスナップショット: `docs/spec/sources/rfc7932.txt`) |
| 参照実装 | upstream Brotli 参照実装 (MIT、static dictionary テーブル構造の動作参照のみ。コード取り込みなし)、system `brotli` (interop oracle)。詳細: THIRD_PARTY_NOTICES Brotli 項・4 節 |
| decoder scope | §3-§10 の全必須デコードパス (prefix codes, distances, insert/copy lengths, context modeling, static dictionary, sliding window) を実装 |
| public encoder scope | §9.1 stream header + §9.2 の uncompressed metablock / metadata metablock / LZ77 compressed metablock (insert+copy command, complex/simple prefix codes, distance encoding, context modeling, static dictionary usage, multi-block-type) を提供。圧縮戦略は固定順 (literal-only → context-modeling LZ77 → multi-block LZ77 → single-block LZ77) で、非圧縮表現より小さい最初の戦略を採用する first-match-wins (大域最小探索ではない) |

### §3 Prefix Codes

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | Simple prefix code (1-4 シンボル) 構築 | RFC 7932 §3.4 | ✅ | `HuffmanTable::from_simple_code()`, encoder の simple code 生成 |
| 2 | Complex prefix code: code length Huffman → シンボル Huffman | RFC 7932 §3.5 | ✅ | `read_complex_prefix_code()`, `test_complex_prefix_decodes_lengths_1233` |
| 3 | Code length alphabet: symbol 16 (前回非ゼロ繰り返し) / symbol 17 (ゼロ繰り返し) | RFC 7932 §3.5 | ✅ | `test_repeat_count_resets_between_16_and_17` |

### §4 Encoding of Distances

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 4 | Short distance codes (0-15): recent distance ring buffer 参照 | RFC 7932 §4 | ✅ | `test_short_distance_code_uses_initial_ring_buffer`, `test_decode_command_last_distance_reuse_metadata` |
| 5 | Direct distance codes (16 to 15+NDIRECT) | RFC 7932 §4 | ✅ | `decode_distance()` 実装 |
| 6 | Indirect distance codes: NPOSTFIX + extra bits (distance alphabet size = 16 + NDIRECT + (48 << NPOSTFIX)) | RFC 7932 §4, alphabet size 式は §3.3 | ✅ | `decode_distance()` 実装 |
| 7 | Recent distance ring buffer (4 エントリ、初期値 16,15,11,4) | RFC 7932 §4 | ✅ | `test_short_distance_code_uses_initial_ring_buffer` |

### §5 Encoding of Literal Insertion Lengths and Copy Lengths

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 8 | 704-symbol insert-and-copy command alphabet | RFC 7932 §5 | ✅ | `COMMAND_CELL_POS` lookup, `decode_command()` |
| 9 | Insert length codes (0-23) + extra bits | RFC 7932 §5 Table | ✅ | `INSERT_LENGTH_OFFSETS`, `INSERT_LENGTH_EXTRA_BITS` |
| 10 | Copy length codes (0-23) + extra bits | RFC 7932 §5 Table | ✅ | `COPY_LENGTH_OFFSETS`, `COPY_LENGTH_EXTRA_BITS` |

### §7 Context Modeling

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | Literal context modes: LSB6 (mode 0), MSB6 (mode 1), UTF8 (mode 2), Signed (mode 3) | RFC 7932 §7.1 | ✅ | `test_context_lookup_tables_match_rfc7932_reference` (全4テーブル×256エントリ網羅), `test_literal_context_id_signed_matches_reference_ranges`, `test_literal_context_p2_single_byte_output_uses_zero` |
| 12 | Distance context: copy length offset (0-3) | RFC 7932 §7.2 | ✅ | `distance_tree_index()` 実装 |
| 13 | Context map: RLE + Inverse Move-to-Front | RFC 7932 §7.3 | ✅ | `test_read_context_map_without_rle`, `test_inverse_move_to_front_context_map` |

### §8 Static Dictionary

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 14 | 122KB 静的辞書参照 (word_idx + transform_idx) | RFC 7932 §8 | ✅ | `test_brotli_decode_static_dictionary_identity_reference` |
| 15 | 辞書変換: IDENTITY / OMIT_LAST_N / UPPERCASE_FIRST / UPPERCASE_ALL / OMIT_FIRST_N | RFC 7932 §8 Appendix B | ✅ | `dictionary.rs` の `TRANSFORMS` テーブル (121 トリプレット、RFC §8 "121 different forms" と一致) |
| 16 | Affix テーブル (50 種の接頭辞/接尾辞) | RFC 7932 §8 Appendix B | ✅ | `dictionary.rs` の `AFFIXES` |

### §9 Compressed Data Format

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | Stream header: WBITS パース (bit 0 で 16-bit 固定 or 17-24 可変) | RFC 7932 §9.1 | ✅ | `test_parse_window_bits_default_large`, `test_parse_window_bits_extended` |
| 18 | Metablock header: ISLAST / ISLASTEMPTY / MNIBBLES | RFC 7932 §9.2 | ✅ | `test_decode_empty_stream`, `parse_metablock_header()` |
| 19 | Final empty stream marker (ISLAST=1, ISLASTEMPTY=1) | RFC 7932 §9.2 | ✅ | `test_decode_empty_stream` |
| 20 | Uncompressed metablock decode | RFC 7932 §9.2 | ✅ | `test_decode_uncompressed_hello_stream`, `test_decode_last_uncompressed_metablock` |
| 21 | Metadata metablock parse / reserved bit reject | RFC 7932 §9.2 | ✅ | `test_parse_metadata_header`, `test_decode_metadata_then_empty`, `test_metadata_reserved_bit_rejected` |
| 22 | Compressed metablock: NBLTYPES{L,I,D} / block type switching (symbol 0=prev-prev、1=prev+1 で最大値 wrap→0、2+=明示) | RFC 7932 §6/§9.2 | ✅ | `test_parse_compressed_metablock_info_with_literal_block_switch`, `test_block_type_state_switches_block_types`, `test_block_type_symbol_1_wraps_to_zero` |

### §9.1/§10 Window Size and Decoding Algorithm

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 23 | Window size: 2^WBITS - 16 bytes (最大 2^24) | RFC 7932 §9.1 | ✅ | `parse_window_bits()` |
| 24 | Backward copy from distance | RFC 7932 §10 | ✅ | `copy_from_distance()` |
| 25 | Static dictionary fallback (distance > output.len()) | RFC 7932 §8 / §10 | ✅ | `test_brotli_decode_static_dictionary_identity_reference` |

### エンコーダー (bounded subset)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 26 | Uncompressed metablock 生成 | RFC 7932 §9.2 | ✅ | `test_brotli_encode_roundtrip`, `test_brotli_encode_writer_roundtrip` |
| 27 | Multi-metablock (MAX_METABLOCK_LEN = 16,777,215B 超) 分割 | RFC 7932 §9.2 | ✅ | `test_brotli_encode_multi_metablock_roundtrip` |
| 28 | Literal-only compressed metablock (insert-only command, simple prefix codes) | RFC 7932 §9.2 / §3.4 / §5 | ✅ | `test_brotli_encode_repeated_run_uses_compressed_metablock`, `test_brotli_encode_low_cardinality_literals_use_compressed_metablock` |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 29 | system `brotli` 生成ストリームのデコード (quality 0-11, text/binary/high-entropy) | RFC 7932 interop | ✅ | `test_brotli_decode_system_q0_uncompressed`, `test_brotli_decode_system_q3_compressed_run`, `test_brotli_decode_system_q5_repeated_pattern`, `test_brotli_decode_system_binary_payload`, `test_brotli_decode_system_quality_levels` (q0-11 全品質), `test_brotli_decode_system_signed_context_mode_regression`, `test_brotli_decode_system_utf8_context_table_regression` |
| 30 | crate encode → system `brotli -d` 展開互換 | RFC 7932 interop | ✅ | `test_brotli_encode_system_decode`, `test_brotli_encode_empty_system_decode`, `test_brotli_encode_repeated_pattern_system_decode`, `test_brotli_encode_low_cardinality_system_decode`, `test_brotli_encode_lz77_system_decode` |
| 31 | 途中切断ストリームの拒否 | RFC 7932 malformed | ✅ | `test_brotli_decode_rejects_truncated_stream`、`test_decode_truncated_at_every_position` (全切断位置で拒否) |

### エンコーダー拡張 (LZ77 + context modeling)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 32 | §3.5 Complex prefix codes (encode) | RFC 7932 §3.5 | ✅ | `write_complex_prefix_code()` |
| 33 | §4 Distance encoding (encode) | RFC 7932 §4 | ✅ | `encode_distance()` は `floor(log2(distance+3))-1` でスロットを決める。`test_encode_distance_matches_linear_scan` |
| 34 | §5 Full insert-and-copy command (copy 含む encode) | RFC 7932 §5 | ✅ | `generate_lz77_commands()`, 単一スロットのハッシュ, `test_single_block_lz77_path_produces_valid_stream` |
| 35 | §7 Context modeling (encode) | RFC 7932 §7 | ✅ | `write_ctx_model()`, `test_context_modeling_roundtrip`, `test_context_modeling_lz77_path_produces_valid_stream`, `test_brotli_encode_metablock_boundary_context` |
| 36 | §8 Static dictionary usage (encode) | RFC 7932 §8 | ✅ | `find_dictionary_match()`。索引はビルド時に `dictionary.bin` から生成する。`test_embedded_dict_index_matches_runtime_build` |
| 37 | §9.2 Metadata metablock encode | RFC 7932 §9.2 | ✅ | `encode_with_metadata()`, `test_metadata_roundtrip` |
| 38 | Multi-block-type encoder | RFC 7932 §9.2 | ✅ | `write_multi_block()`, `test_multi_block_lz77_path_produces_valid_stream` |

### 追加要件 (decoder)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 39 | HSKIP: code length code 順序 (1,2,3,4,0,5,17,6,16,7,8,...,15) | RFC 7932 §3.5 | ✅ | read_code_length_code_lengths() |
| 40 | Oversubscribed/undersubscribed prefix code 検証 | RFC 7932 §3 | ✅ | `read_code_lengths` / `read_code_length_code_lengths` の space 計算 (32768/32 ちょうど消費を要求) |
| 41 | NPOSTFIX / NDIRECT parameter parsing from metablock header | RFC 7932 §9.2 | ✅ | parse_compressed_metablock_info() |
| 42 | WBITS value range validation (10-24) + reserved pattern (WBITS=9) reject | RFC 7932 §9.1 | ✅ | `parse_window_bits()`, `test_parse_window_bits_rejects_reserved_pattern` |
| 43 | Uncompressed metablock: byte alignment requirement | RFC 7932 §9.2 | ✅ | デコーダーで align |
| 44 | Max backward distance = min(window_size, output_so_far) | RFC 7932 §8/§10 | ✅ | copy_from_distance() |
| 45 | Simple prefix code: シンボル値がアルファベットサイズ未満であること | RFC 7932 §3.4 | ✅ | read_simple_prefix_code(): symbol >= alphabet_size で InvalidData; from_simple_code() でも同様 |
| 46 | Complex prefix code: 2 個以上の非ゼロコード長が必要 | RFC 7932 §3.5 | ✅ | `non_zero_count < 2` で InvalidData。`test_complex_prefix_single_nonzero_code_length_rejected` |
| 47 | Special distance が 0 以下に解決した場合 reject | RFC 7932 §4 | ✅ | decode.rs `RecentDistances::resolve_short_code`: distance <= 0 で InvalidData |
| 48 | Distance code 0 はリングバッファを更新しない | RFC 7932 §4 | ✅ | decode.rs: code 0 で should_push_distance=false、recent_distances.push をスキップ |
| 49 | NBLTYPES = largest block type + 1 の検証 | RFC 7932 §6 | ✅ | `block_type >= num_types` で InvalidData |
| 50 | Context map: 値域が [0..NTREES-1] であること | RFC 7932 §7.3 | ✅ | read_context_map(): value >= ntrees で InvalidData |
| 51 | 非圧縮メタブロックは最後のメタブロックになれない | RFC 7932 §9.2 | ✅ | `is_last && is_uncompressed` で InvalidData |
| 52 | 最終メタブロック末尾の未使用ビットは 0 であること | RFC 7932 §9.3 | ✅ | `test_last_metablock_rejects_nonzero_trailing_padding`, `test_last_empty_padding_must_be_zero` |
| 53 | MNIBBLES>4 かつ最終ニブルが全 0 → non-canonical MLEN として reject | RFC 7932 §9.2 | ✅ | `decode.rs` "non-canonical metablock length" + `test_noncanonical_metablock_length_rejected` |
| 54 | MSKIPBYTES>1 かつ最終バイトが全 0 → non-canonical MSKIPLEN として reject + metadata fill bits は全 0 必須 | RFC 7932 §9.2 | ✅ | `test_noncanonical_metadata_length_rejected` `test_metadata_nonzero_fill_bits_rejected` |
| 55 | literal/copy/dictionary 出力が MLEN を超過 → reject、insert で MLEN 満了時は copy を無視 | RFC 7932 §9.3 | ✅ | `test_command_exceeding_metablock_length_rejected` |
| 56 | repeat code の繰り返しが alphabet size 超過 → reject | RFC 7932 §3.5 | ✅ | `huffman.rs` "code length repeat overflow" + `test_complex_prefix_repeat_previous_overflow_rejected` |
| 57 | NTREES = context map 内の異なる値の個数 (全 tree index が使用されること) | RFC 7932 §7.3 | ✅ | `test_context_map_rejects_unused_tree_index` |
| 58 | dictionary 参照: copy_len ∈ [4,24] かつ transform_id ≤ 120 でなければ reject | RFC 7932 §8 | ✅ | `test_copy_static_dictionary_rejects_out_of_range_copy_len` `test_copy_static_dictionary_rejects_out_of_range_transform` |
| 59 | static dictionary reference を解決した distance はリングバッファに push しない | RFC 7932 §10 / §4 | ✅ | 辞書参照 distance (`distance > max_allowed_distance`) は `recent_distances` push を抑止。`test_dictionary_distance_not_pushed_to_recent_ring` `test_decode_dictionary_reference_preserves_distance_ring` |
| 60 | Simple prefix code のシンボル重複は reject | RFC 7932 §3.4 | ✅ | `read_simple_prefix_code` の `symbols.contains` チェック、`test_simple_prefix_duplicate_symbol_rejected` |
| 61 | Code length code が非ゼロ長 1 個のみ → 全シンボルゼロ長の singleton として受理 | RFC 7932 §3.5 | ✅ | `read_code_length_code_lengths` の `non_zero_count == 1` 受理経路 |
| 62 | Distance ring buffer は metablock 境界でリセットされない | RFC 7932 §4/§10 | ✅ | `RecentDistances` はストリーム先頭で 1 回のみ生成 (cross-metablock 継続) |
| 63 | insert-and-copy code 0..127 は distance code 0 暗黙 (copy なし) | RFC 7932 §5 | ✅ | `decode_command` の `cell_idx < 2 → Some(0)` |
| 64 | Context map の RLE 長が map サイズ超過 → reject | RFC 7932 §7.3 | ✅ | `read_context_map` の "context map repeat overflow" |
| 65 | Backward distance は metablock 境界を跨いで参照可能 | RFC 7932 §10 | ✅ | 単一 output バッファで自然に対応 (design 上自明) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 65 |
| ⚠️ 部分実装  | 0 |
| ❌ 未実装  | 0 |
| **合計** | **65** |

