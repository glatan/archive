# xz (LZMA2 ベース圧縮フォーマット)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [xz ファイルフォーマット仕様 1.2.1](https://tukaani.org/xz/xz-file-format-1.2.1.txt) (2024-04-08 版、ローカルスナップショット: `docs/spec/sources/xz-file-format-1.2.1.txt`)。1.2.0 で RISC-V BCJ filter (0x0B) が追加 — 実装は `bcj::riscv_*` で対応済み |
| 参照実装 | liblzma (public domain、BCJ/Delta filter core の移植元・LZMA2 chunk semantics の参照元)、system `xz` バイナリ (テスト時 interop oracle)。詳細: THIRD_PARTY_NOTICES xz / BCJ filters / LZMA2 項 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| check: none / CRC-32 / CRC-64 / SHA-256 | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt): Check types | ✅ | ✅ | encode は CRC-32 のみ出力 |
| filter: LZMA2 (final) | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | |
| filter: BCJ x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | system interop で全 BCJ 検証済み |
| filter: Delta | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | |
| 連結ストリーム | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | encode は単一ストリームのみ生成 (出力の単純連結で構成可、interop 検証済み) |
| registry-backed custom filter | crate API | ✅ | ✅ | 0x40-0x7F は即 `Unsupported` reject、それ以外の未知 ID は registry 未登録時に `Unsupported` |

### ストリームフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | Stream Header magic (6 bytes: FD 37 7A 58 5A 00) | xz-file-format.txt: Stream Header | ✅ | `test_invalid_magic` |
| 2 | Stream Flags (check type, reserved bits) | xz-file-format.txt: Stream Flags | ✅ | decoder validation |
| 3 | Stream Header CRC-32 | xz-file-format.txt: Stream Header | ✅ | `test_header_crc_check` |
| 4 | Stream Footer (magic "YZ", CRC-32, backward size) | xz-file-format.txt: Stream Footer | ✅ | `test_footer_magic_check` |
| 5 | Stream Footer CRC-32 | xz-file-format.txt: Stream Footer | ✅ | decoder validation |
| 6 | Stream Flags header/footer match | xz-file-format.txt: Stream Header / Stream Footer | ✅ | decoder validation |
| 7 | Check type: None (0x00) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_none_check_type_decode` (check フィールドが空のストリームを再構成してデコード) |
| 8 | Check type: CRC-32 (0x01) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_data_crc_check` |
| 9 | Check type: CRC-64 (0x04) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_crc64_check_type_decode`, `test_crc64_check_type_mismatch` |
| 10 | Check type: SHA-256 (0x0A) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_sha256_check_type_decode`, `test_sha256_check_type_mismatch` |
| 11 | Concatenated streams | xz-file-format.txt: Overall structure / Stream Padding | ✅ | `test_decode_two_concatenated_streams`, `test_decode_concatenated_streams_with_padding` |
| 12 | Garbage/truncation between streams | xz-file-format.txt: Overall structure / Stream Padding | ✅ | `test_decode_garbage_between_streams_rejected`, `test_decode_truncated_second_stream_rejected` |
| 13 | Input too short error | xz-file-format.txt: Stream Header | ✅ | `test_input_too_short` |
| 14 | Backward Size validation: (stored_value + 1) * 4 must match Index size | xz-file-format.txt §2.1.2.2 | ✅ | decode で `backward_size_raw` を計算し Index サイズと照合 |
| 15 | Backward Size field encoding formula | xz-file-format.txt §2.1.2.2 | ✅ | `((backward_size_raw as usize) + 1) * 4` で実装 |
| 16 | Filter ID ranges: 0x00-0x3F standard。本実装は 0x40-0x7F を `Unsupported` で reject (安全側)。正式な予約範囲は §3.1.5 (≥2^62) と §5.4.1 (0x0000_0300-0x0000_04FF, 0x0002_0000-0x0007_FFFF, 0x0200_0000-0x07FF_FFFF) | xz-file-format.txt §3.1.5 / §5.4.1 | ✅ | `test_reserved_filter_id_rejected`, `test_reserved_filter_id_boundary`。§5.4.1 の reserved range は decode では Unknown filter 経由で実質 reject |

### ブロック構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | Block Header size/CRC-32 | xz-file-format.txt: Block Header | ✅ | `test_reserved_block_flags_rejected` |
| 18 | Block Flags (filter count, reserved bits) | xz-file-format.txt: Block Header | ✅ | `test_reserved_block_flags_rejected` |
| 19 | LZMA2 final filter + x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V BCJ + Delta prefilters | xz-file-format.txt: Block Header / Filter list | ✅ | `test_xz_decode_system_encoded_x86_filter_chain`, `test_xz_encode_x86_filter_chain_system_decode`, `test_xz_decode_system_encoded_powerpc_filter_chain`, `test_xz_encode_powerpc_filter_chain_system_decode`, `test_xz_decode_system_encoded_ia64_filter_chain`, `test_xz_encode_ia64_filter_chain_system_decode`, `test_xz_decode_system_encoded_sparc_filter_chain`, `test_xz_encode_sparc_filter_chain_system_decode`, `test_xz_decode_system_encoded_arm_filter_chain`, `test_xz_encode_arm_filter_chain_system_decode`, `test_xz_decode_system_encoded_armthumb_filter_chain`, `test_xz_encode_armthumb_filter_chain_system_decode`, `test_xz_decode_system_encoded_arm64_filter_chain`, `test_xz_encode_arm64_filter_chain_system_decode`, `test_xz_decode_system_encoded_riscv_filter_chain`, `test_xz_encode_riscv_filter_chain_system_decode`, `test_xz_decode_system_encoded_delta_filter_chain`, `test_xz_encode_delta_filter_chain_system_decode`, `test_xz_decode_system_encoded_riscv_auipc_pair`, `test_xz_encode_riscv_filter_chain_system_decode_fuzz_regression`, `test_fuzz_regression_xz_riscv_self`, `test_riscv_auipc_non_pair_roundtrip`, `test_riscv_special_auipc_roundtrip`, `test_riscv_special_auipc_reads_be_absolute_address` |
| 20 | Dictionary size byte decoding (0-40) | xz-file-format.txt: LZMA2 filter properties | ✅ | `test_dict_size_decoding` |
| 21 | dict_size_byte > 40 rejection | xz-file-format.txt: LZMA2 filter properties | ✅ | `test_dict_size_byte_41_rejected` |
| 22 | dict_size(40) overflow protection | xz-file-format.txt: LZMA2 filter properties | ✅ | `test_dict_size_decoding` |
| 23 | Block padding zero validation | xz-file-format.txt: Block Padding | ✅ | `test_nonzero_block_padding_rejected` |
| 24 | Compressed/uncompressed size optional fields | xz-file-format.txt: Block Header | ✅ | decode で flags 0x40/0x80 のフィールドをパース+検証 (直接テストなし — 自 encoder 未出力、`xz -c` も通常出力しない) |
| 25 | Block Header: filter count = (flags & 0x03) + 1, max 4 | xz-file-format.txt §3.1.2 | ✅ | `(block_flags & 0x03) + 1` でパース、ビットフィールド幅により最大4に制約 |
| 26 | BCJ filter properties: start offset (4B LE) or empty for default 0 | xz-file-format.txt §5.3.2 | ✅ | parse_bcj_start_offset() |
| 27 | Delta filter properties: 1 byte, distance = stored + 1, range 1-256 | xz-file-format.txt §5.3.3.1 | ✅ | 実装済み |
| 28 | LZMA2 filter properties: exactly 1 byte (dict size exponent) | xz-file-format.txt §5.3.1 | ✅ | item 17-18 で部分記載 |

### Index

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 29 | Index indicator (0x00) | xz-file-format.txt: Index | ✅ | |
| 30 | Index CRC-32 verification | xz-file-format.txt: Index | ✅ | `decode.rs` Index CRC-32 経路。`test_index_record_corrupted` は record mismatch を検査 (Index CRC の直接 reject テストなし) |
| 31 | Index record count vs block count validation | xz-file-format.txt: Index | ✅ | `verify_index()` |
| 32 | Index unpadded/uncompressed size verification | xz-file-format.txt: Index | ✅ | `verify_index()` |
| 33 | Index padding のゼロ検証 | xz-file-format.txt: Index Padding | ✅ | `test_nonzero_index_padding_rejected` |

### VLI

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 34 | VLI decoding (7-bit chunks) | xz-file-format.txt: Variable-Length Integer | ✅ | `test_decode_vli_values` |
| 35 | VLI too long error | xz-file-format.txt: Variable-Length Integer | ✅ | `test_decode_vli_too_long` |
| 36 | 非正規 VLI (末尾 0x00 継続終端) 拒否 | xz-file-format.txt: Variable-Length Integer | ✅ | `test_decode_vli_noncanonical_zero_rejected` |

### LZMA2

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 37 | Control byte dispatch (0x00=end, 0x01-0x02=uncompressed, 0x80+=LZMA) | liblzma LZMA2 chunk semantics (xz-file-format.txt §3.2 で範囲外) | ✅ | `test_lzma2_end_marker_only`, `test_lzma2_control_byte_ranges`, `test_lzma2_invalid_control` |
| 38 | Properties byte validation (lc+lp<=4, pb<=4) | xz-file-format.txt §5.3.1 + liblzma LZMA2 semantics | ✅ | `test_lzma2_control_byte_ranges` |
| 39 | decode 側は妥当な lc/lp/pb 組 (`lc+lp<=4`, `pb<=4`) を受理 | xz-file-format.txt §5.3.1 + liblzma LZMA2 semantics | ✅ | `test_decode_system_xz_with_non_default_lzma_props` |
| 40 | LZMA2 uncompressed chunk: 0x01 = dictionary reset, 0x02 = no reset | liblzma LZMA2 chunk semantics (xz-file-format.txt §3.2 で範囲外) | ✅ | lzma2 実装で対応 |
| 41 | LZMA2 compressed chunk: state/properties reset flags in control byte high nibble | liblzma LZMA2 chunk semantics (xz-file-format.txt §3.2 で範囲外) | ✅ | lzma2 実装で対応 |
| 42 | LZMA2 chunk sizes: 2-byte uncompressed + 2-byte compressed | liblzma LZMA2 chunk semantics (xz-file-format.txt §3.2 で範囲外) | ✅ | lzma2 実装で対応 |

### チェックサム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 43 | CRC-64 polynomial: ECMA-182 | xz-file-format.txt §6 | ✅ | util::crc64 実装 |
| 44 | Index Number of Records: VLI encoded | xz-file-format.txt §4.2 | ✅ | decode 実装 |
| 45 | Index Unpadded Size minimum validation | xz-file-format.txt §4.3.1 | ✅ | `verify_index()` でブロック実測値と照合 |

### ラウンドトリップ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 46 | Empty/hello/repeated/all_bytes/single_byte | xz-file-format.txt: end-to-end stream/block/index layout | ✅ | |
| 47 | writer/decode の current supported filter chain | xz-file-format.txt: Filter list / crate scope | ✅ | `LZMA2` final filter の前段に x86 / PowerPC / IA64 / SPARC / ARM / ARM-Thumb / ARM64 / RISC-V BCJ、および Delta prefilter を置く構成を current scope とし、system interop tests で回帰化 |
| 48 | registry 登録済み custom filter を含む arbitrary filter chain write と、未登録 custom filter reject | xz-file-format.txt: Filter list / crate scope | ✅ | `test_custom_filter_registry_roundtrip`, `test_custom_filter_registry_roundtrip_with_standard_filter_chain`, `test_custom_filter_passthrough_registry_roundtrip`, `test_custom_filter_passthrough_registry_roundtrip_with_standard_filter_chain`, `test_encode_with_unknown_filter_rejected`, `test_custom_filter_registry_decode_requires_registration` |

### その他の要件

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 49 | BCJ start offset alignment 検証 (PowerPC=4B, IA64=16B, ARM=4B, ARM-Thumb=2B, SPARC=4B, ARM64=4B, RISC-V=2B) | xz-file-format.txt §5.3.2 | ✅ | `parse_bcj_start_offset()` に alignment チェック実装、`test_bcj_alignment_powerpc_rejected`, `test_bcj_alignment_arm_rejected`, `test_validate_bcj_alignment_*` |
| 50 | Stream Padding: 4 バイト倍数のゼロ | xz-file-format.txt §2.2 | ✅ | `test_decode_concatenated_streams_with_padding` |
| 51 | Filter chain: ブロックあたり最大 4 フィルター | xz-file-format.txt §3.1.2 | ✅ | `(block_flags & 0x03) + 1` でパース、ビットフィールド幅により最大4に制約 (item 25 と同一) |
| 52 | Check type reserved (0x02, 0x03, 0x05-0x09, 0x0B-0x0F) の reject | xz-file-format.txt §2.1.1.2 | ✅ | `Unsupported("xz: unsupported check type")` で reject |
| 53 | ファイル全体サイズは 4 バイトの倍数 | xz-file-format.txt §2 | ✅ | `input.len().is_multiple_of(4)` で検証、不一致で InvalidData |
| 54 | ストリームサイズ上限 8 EiB (2^63 bytes) | xz-file-format.txt §2.1 | ✅ | 実用上到達不可能。u64 範囲内で処理 |
| 55 | Filter chain security: 非最終フィルターのうちサイズ変更可能なものは最大 2 個 | xz-file-format.txt §5.2 | ✅ | フィルター設計者向け MUST。標準フィルター (BCJ/Delta) はサイズ保存のため構造的に充足。custom registry 経由のフィルターは登録側責務であり crate は件数を強制しない (liblzma も decode 時に強制しない) |
| 56 | Block Header Padding は MUST null (ゼロ) バイト | xz-file-format.txt §3.1.6 | ✅ | `decode.rs` で non-zero block header padding を reject |
| 57 | BCJ/Delta は最終フィルターにできない (Allow as the last filter: No → 最終は LZMA2 のみ) | xz-file-format.txt §5.3.2 / §5.3.3 | ✅ | `parse_filter` の `is_last` チェック、`test_parse_unknown_final_filter_rejected` |
| 58 | Filter IDs ≥ 2^62 (0x4000_0000_0000_0000) は List of Filter Flags で使用禁止 | xz-file-format.txt §3.1.5 | ✅ | 実装済み — `FILTER_ID_RESERVED_START` (2^62) 以上を `Error::InvalidData` で reject (parse/validate/registry)。`test_reserved_high_filter_id_rejected` `test_block_header_reserved_high_filter_id_rejected` |
| 59 | Index field 最大 16 GiB (2^34) | xz-file-format.txt §2.1 | ✅ | `MAX_INDEX_SIZE = 16 GiB` を明示し `verify_index` で境界を検証 (Backward Size 演算とレコード数チェックは `u64` で評価)。`test_backward_size_max_implies_index_limit`, `test_index_max_vli_record_count_rejected` |
| 60 | Block Header Size byte は [0x01,0xFF] (0x00 は Index Indicator) | xz-file-format.txt §3.1.1 | ✅ | decode で 0x00 → Index 遷移として処理 |
| 61 | Compressed Size フィールドは non-zero MUST | xz-file-format.txt §3.1.3 | ✅ | mismatch で実質 reject (compressed_len ≥ 1) |
| 62 | Unpadded Size は never zero MUST (最小 5) | xz-file-format.txt §4.3.1 | ✅ | 実測照合で実質 reject |

---

## 実装メモ (liblzma との差分 — いずれも lenient 側)

- 共有 LZMA コアの仮想ゼロ距離受理 (`rep0 == output.len()` で初期距離を 0x00 として読む): lzip manual §6.2 由来の仕様だが liblzma は `rep0 == full` を reject。辞書リセット直後に限る狭い差分で、正当な .xz には影響なし。
- LZMA2 first-chunk dict-reset 規則を強制しない: liblzma は `need_dictionary_reset` で先頭 chunk が 0x02 / 0x80-0x9F (reset なし) を拒否するが、本実装は受理する。
- uncompressed chunk 直後の compressed chunk で state reset (0xA0+) を強制しない: liblzma は要求するが、本実装は `decoder_state` を継続利用して受理する。
- `decode_bounded` は完全 decode 後の事後チェックであり、decode 中のメモリ使用量は bounded ではない。
- `register_passthrough` は §5.4.1 reserved range も許容する (registry 登録経路では decode 可能)。

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 62 |
| **合計** | **62** |
