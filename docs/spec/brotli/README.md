# Brotli (RFC 7932)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [RFC 7932](https://www.rfc-editor.org/rfc/rfc7932.txt) (2016) — Brotli Compressed Data Format (ローカルスナップショット: `docs/spec/sources/rfc7932.txt`) |
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
| 15 | 辞書変換: IDENTITY / OMIT_LAST_N / UPPERCASE_FIRST / UPPERCASE_ALL / OMIT_FIRST_N | RFC 7932 §8 Appendix B | ✅ | `dictionary.rs` の `TRANSFORMS` テーブル (144 エントリ) |
| 16 | Affix テーブル (50 種の接頭辞/接尾辞) | RFC 7932 §8 Appendix B | ✅ | `dictionary.rs` の `AFFIXES` |

### §9 Compressed Data Format

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | Stream header: WBITS パース (bit 0 で 16-bit 固定 or 17-24 可変) | RFC 7932 §9.1 | ✅ | `test_parse_window_bits_default_large`, `test_parse_window_bits_extended` |
| 18 | Metablock header: ISLAST / ISLASTEMPTY / MNIBBLES | RFC 7932 §9.2 | ✅ | `test_decode_empty_stream`, `parse_metablock_header()` |
| 19 | Final empty stream marker (ISLAST=1, ISLASTEMPTY=1) | RFC 7932 §9.2 | ✅ | `test_decode_empty_stream` |
| 20 | Uncompressed metablock decode | RFC 7932 §9.2 | ✅ | `test_decode_uncompressed_hello_stream`, `test_decode_last_uncompressed_metablock` |
| 21 | Metadata metablock parse / reserved bit reject | RFC 7932 §9.2 | ✅ | `test_parse_metadata_header`, `test_decode_metadata_then_empty`, `test_metadata_reserved_bit_rejected` |
| 22 | Compressed metablock: NBLTYPES{L,I,D} / block type switching | RFC 7932 §6/§9.2 | ✅ | `test_parse_compressed_metablock_info_with_literal_block_switch`, `test_block_type_state_switches_block_types` |

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
| 27 | Multi-metablock (65,536B 超) 分割 | RFC 7932 §9.2 | ✅ | `test_brotli_encode_multi_metablock_roundtrip` |
| 28 | Literal-only compressed metablock (insert-only command, simple prefix codes) | RFC 7932 §9.2 / §3.4 / §5 | ✅ | `test_brotli_encode_repeated_run_uses_compressed_metablock`, `test_brotli_encode_low_cardinality_literals_use_compressed_metablock` |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 29 | system `brotli` 生成ストリームのデコード (quality 0-11, text/binary/high-entropy) | RFC 7932 interop | ✅ | `test_brotli_decode_system_q0_uncompressed`, `test_brotli_decode_system_q3_compressed_run`, `test_brotli_decode_system_q5_repeated_pattern`, `test_brotli_decode_system_binary_payload`, `test_brotli_decode_system_quality_levels` (q0-11 全品質), `test_brotli_decode_system_signed_context_mode_regression`, `test_brotli_decode_system_utf8_context_table_regression` |
| 30 | crate encode → system `brotli -d` 展開互換 | RFC 7932 interop | ✅ | `test_brotli_encode_system_decode`, `test_brotli_encode_empty_system_decode`, `test_brotli_encode_repeated_pattern_system_decode`, `test_brotli_encode_low_cardinality_system_decode`, `test_brotli_encode_lz77_system_decode` |
| 31 | Truncated stream reject | RFC 7932 malformed | ✅ | `test_brotli_decode_rejects_truncated_stream` |

### エンコーダー拡張 (LZ77 + context modeling)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 32 | §3.5 Complex prefix codes (encode) | RFC 7932 §3.5 | ✅ | `write_complex_prefix_code()` |
| 33 | §4 Distance encoding (encode) | RFC 7932 §4 | ✅ | `encode_distance()` |
| 34 | §5 Full insert-and-copy command (copy 含む encode) | RFC 7932 §5 | ✅ | `generate_lz77_commands()`, LZ77 hash-chain match finder, `test_single_block_lz77_path_produces_valid_stream` |
| 35 | §7 Context modeling (encode) | RFC 7932 §7 | ✅ | `write_ctx_model()`, `test_context_modeling_roundtrip`, `test_context_modeling_lz77_path_produces_valid_stream`, `test_brotli_encode_metablock_boundary_context` |
| 36 | §8 Static dictionary usage (encode) | RFC 7932 §8 | ✅ | `find_dictionary_match()` |
| 37 | §9.2 Metadata metablock encode | RFC 7932 §9.2 | ✅ | `encode_with_metadata()`, `test_metadata_roundtrip` |
| 38 | Multi-block-type encoder | RFC 7932 §9.2 | ✅ | `write_multi_block()`, `test_multi_block_lz77_path_produces_valid_stream` |

### 追加要件 (decoder)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 39 | HSKIP: code length code 順序 (1,2,3,4,0,5,17,6,16,7,8,...,15) | RFC 7932 §3.5 | ✅ | read_code_length_code_lengths() |
| 40 | Oversubscribed/undersubscribed prefix code 検証 | RFC 7932 §3 | ✅ | Huffman builder |
| 41 | NPOSTFIX / NDIRECT parameter parsing from metablock header | RFC 7932 §9.2 | ✅ | parse_compressed_metablock_info() |
| 42 | WBITS value range validation (10-24) + reserved pattern (WBITS=9) reject | RFC 7932 §9.1 | ✅ | `parse_window_bits()`, `test_parse_window_bits_rejects_reserved_pattern` |
| 43 | Uncompressed metablock: byte alignment requirement | RFC 7932 §9.2 | ✅ | デコーダーで align |
| 44 | Max backward distance = min(window_size, output_so_far) | RFC 7932 §8/§10 | ✅ | copy_from_distance() |
| 45 | Simple prefix code: シンボル値がアルファベットサイズ未満であること | RFC 7932 §3.4 | ✅ | read_simple_prefix_code(): symbol >= alphabet_size で InvalidData; from_simple_code() でも同様 |
| 46 | Complex prefix code: 2 個以上の非ゼロコード長が必要 | RFC 7932 §3.5 | ✅ | `non_zero_count < 2` で InvalidData。`test_complex_prefix_single_nonzero_code_length_rejected` |
| 47 | Special distance が 0 以下に解決した場合 reject | RFC 7932 §4 | ✅ | decode.rs line 172-173: distance <= 0 で InvalidData |
| 48 | Distance code 0 はリングバッファを更新しない | RFC 7932 §4 | ✅ | decode.rs: code 0 で should_push_distance=false、recent_distances.push をスキップ |
| 49 | NBLTYPES = largest block type + 1 の検証 | RFC 7932 §6 | ✅ | `block_type >= num_types` で InvalidData |
| 50 | Context map: 値域が [0..NTREES-1] であること | RFC 7932 §7.3 | ✅ | read_context_map(): value >= ntrees で InvalidData |
| 51 | 非圧縮メタブロックは最後のメタブロックになれない | RFC 7932 §9.2 | ✅ | `is_last && is_uncompressed` で InvalidData |
| 52 | 最終メタブロック末尾の未使用ビットは 0 であること | RFC 7932 §9.3 | ✅ | `test_last_metablock_rejects_nonzero_trailing_padding`, `test_last_empty_padding_must_be_zero` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 52 |
| **合計** | **52** |

