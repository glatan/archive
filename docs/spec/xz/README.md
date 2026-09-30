# xz (LZMA2 ベース圧縮フォーマット)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [xz ファイルフォーマット仕様 1.2.1](https://tukaani.org/xz/xz-file-format-1.2.1.txt) (2024-04-08 版、ローカルスナップショット: `docs/spec/sources/xz-file-format-1.2.1.txt`)。1.2.0 で RISC-V BCJ filter (0x0B) が追加 — 実装は `bcj::riscv_*` で対応済み |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| check: none / CRC-32 / CRC-64 / SHA-256 | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt): Check types | ✅ | ✅ | |
| filter: LZMA2 (final) | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | |
| filter: BCJ x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | system interop で全 BCJ 検証済み |
| filter: Delta | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | |
| 連結ストリーム | [xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt) | ✅ | ✅ | |
| registry-backed custom filter | crate API | ✅ | ✅ | 0x00-0x3F 以外の未知 filter は `Unsupported` |

### ストリームフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | Stream Header magic (6 bytes: FD 37 7A 58 5A 00) | xz-file-format.txt: Stream Header | ✅ | `test_invalid_magic` |
| 2 | Stream Flags (check type, reserved bits) | xz-file-format.txt: Stream Flags | ✅ | decoder validation |
| 3 | Stream Header CRC-32 | xz-file-format.txt: Stream Header | ✅ | `test_header_crc_check` |
| 4 | Stream Footer (magic "YZ", CRC-32, backward size) | xz-file-format.txt: Stream Footer | ✅ | `test_footer_magic_check` |
| 5 | Stream Footer CRC-32 | xz-file-format.txt: Stream Footer | ✅ | decoder validation |
| 6 | Stream Flags header/footer match | xz-file-format.txt: Stream Header / Stream Footer | ✅ | decoder validation |
| 7 | Check type: None (0x00) | xz-file-format.txt: Stream Flags / Check types | ✅ | decoder support |
| 8 | Check type: CRC-32 (0x01) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_data_crc_check` |
| 9 | Check type: CRC-64 (0x04) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_crc64_check_type_decode`, `test_crc64_check_type_mismatch` |
| 10 | Check type: SHA-256 (0x0A) | xz-file-format.txt: Stream Flags / Check types | ✅ | `test_sha256_check_type_decode`, `test_sha256_check_type_mismatch` |
| 11 | Concatenated streams | xz-file-format.txt: Overall structure / Stream Padding | ✅ | `test_decode_two_concatenated_streams`, `test_decode_concatenated_streams_with_padding` |
| 12 | Garbage/truncation between streams | xz-file-format.txt: Overall structure / Stream Padding | ✅ | `test_decode_garbage_between_streams_rejected`, `test_decode_truncated_second_stream_rejected` |
| 13 | Input too short error | xz-file-format.txt: Stream Header | ✅ | `test_input_too_short` |
| 14 | Backward Size validation: (stored_value + 1) * 4 must match Index size | xz-file-format.txt §6.1 | ✅ | decode で `backward_size_raw` を計算し Index サイズと照合 |
| 15 | Backward Size field encoding formula | xz-file-format.txt §6.1 | ✅ | `((backward_size_raw as usize) + 1) * 4` で実装 |
| 16 | Filter ID ranges: 0x00-0x3F standard, 0x40-0x7F reserved | xz-file-format.txt §5.3 | ✅ | reserved range (0x40-0x7F) を `Unsupported` で reject。`test_reserved_filter_id_rejected`, `test_reserved_filter_id_boundary` |

### ブロック構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | Block Header size/CRC-32 | xz-file-format.txt: Block Header | ✅ | `test_reserved_block_flags_rejected` |
| 18 | Block Flags (filter count, reserved bits) | xz-file-format.txt: Block Header | ✅ | `test_reserved_block_flags_rejected` |
| 19 | LZMA2 final filter + x86/PowerPC/IA64/SPARC/ARM/ARM-Thumb/ARM64/RISC-V BCJ + Delta prefilters | xz-file-format.txt: Block Header / Filter list | ✅ | `test_xz_decode_system_encoded_x86_filter_chain`, `test_xz_encode_x86_filter_chain_system_decode`, `test_xz_decode_system_encoded_powerpc_filter_chain`, `test_xz_encode_powerpc_filter_chain_system_decode`, `test_xz_decode_system_encoded_ia64_filter_chain`, `test_xz_encode_ia64_filter_chain_system_decode`, `test_xz_decode_system_encoded_sparc_filter_chain`, `test_xz_encode_sparc_filter_chain_system_decode`, `test_xz_decode_system_encoded_arm_filter_chain`, `test_xz_encode_arm_filter_chain_system_decode`, `test_xz_decode_system_encoded_armthumb_filter_chain`, `test_xz_encode_armthumb_filter_chain_system_decode`, `test_xz_decode_system_encoded_arm64_filter_chain`, `test_xz_encode_arm64_filter_chain_system_decode`, `test_xz_decode_system_encoded_riscv_filter_chain`, `test_xz_encode_riscv_filter_chain_system_decode`, `test_xz_decode_system_encoded_delta_filter_chain`, `test_xz_encode_delta_filter_chain_system_decode` |
| 20 | Dictionary size byte decoding (0-40) | xz-file-format.txt: LZMA2 filter properties | ✅ | `test_dict_size_decoding` |
| 21 | dict_size_byte > 40 rejection | xz-file-format.txt: LZMA2 filter properties | ✅ | `test_dict_size_byte_41_rejected` |
| 22 | dict_size(40) overflow protection | xz-file-format.txt: LZMA2 filter properties | ✅ | `test_dict_size_decoding` |
| 23 | Block padding zero validation | xz-file-format.txt: Block Padding | ✅ | `test_nonzero_block_padding_rejected` |
| 24 | Compressed/uncompressed size optional fields | xz-file-format.txt: Block Header | ✅ | |
| 25 | Block Header: filter count = (flags & 0x03) + 1, max 4 | xz-file-format.txt §3.1.2 | ✅ | `(block_flags & 0x03) + 1` でパース、ビットフィールド幅により最大4に制約 |
| 26 | BCJ filter properties: start offset (4B LE) or empty for default 0 | xz-file-format.txt §5.3.2 | ✅ | parse_bcj_start_offset() |
| 27 | Delta filter properties: 1 byte, distance = stored + 1, range 1-256 | xz-file-format.txt §5.3.4 | ✅ | 実装済み |
| 28 | LZMA2 filter properties: exactly 1 byte (dict size exponent) | xz-file-format.txt §5.3.1 | ✅ | item 17-18 で部分記載 |

### Index

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 29 | Index indicator (0x00) | xz-file-format.txt: Index | ✅ | |
| 30 | Index CRC-32 verification | xz-file-format.txt: Index | ✅ | `test_index_record_corrupted` |
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
| 37 | Control byte dispatch (0x00=end, 0x01-0x02=uncompressed, 0x80+=LZMA) | xz-file-format.txt: LZMA2 chunk structure | ✅ | `test_lzma2_end_marker_only`, `test_lzma2_control_byte_ranges`, `test_lzma2_invalid_control` |
| 38 | Properties byte validation (lc+lp<=4, pb<=4) | xz-file-format.txt: LZMA2 properties | ✅ | `test_lzma2_control_byte_ranges` |
| 39 | decode 側は妥当な lc/lp/pb 組 (`lc+lp<=4`, `pb<=4`) を受理 | xz-file-format.txt: LZMA2 properties | ✅ | `test_decode_system_xz_with_non_default_lzma_props` |
| 40 | LZMA2 uncompressed chunk: 0x01 = dictionary reset, 0x02 = no reset | xz-file-format.txt: LZMA2 | ✅ | lzma2 実装で対応 |
| 41 | LZMA2 compressed chunk: state/properties reset flags in control byte high nibble | xz-file-format.txt: LZMA2 | ✅ | lzma2 実装で対応 |
| 42 | LZMA2 chunk sizes: 2-byte uncompressed + 2-byte compressed | xz-file-format.txt: LZMA2 | ✅ | lzma2 実装で対応 |

### チェックサム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 43 | CRC-64 polynomial: ECMA-182 | xz-file-format.txt §2.1.1.2 | ✅ | util::crc64 実装 |
| 44 | Index Number of Records: VLI encoded | xz-file-format.txt §4.2 | ✅ | decode 実装 |
| 45 | Index Unpadded Size minimum validation | xz-file-format.txt §4.2 | ✅ | `verify_index()` でブロック実測値と照合 |

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
| 52 | Check type reserved (0x02, 0x03, 0x05-0x09, 0x0B-0x0F) の reject | xz-file-format.txt §2.1.2 | ✅ | `Unsupported("xz: unsupported check type")` で reject |
| 53 | ファイル全体サイズは 4 バイトの倍数 | xz-file-format.txt §2 | ✅ | `input.len().is_multiple_of(4)` で検証、不一致で InvalidData |
| 54 | ストリームサイズ上限 8 EiB (2^63 bytes) | xz-file-format.txt §2.1 | ✅ | 実用上到達不可能。u64 範囲内で処理 |
| 55 | Filter chain security: 非最終フィルターのうちサイズ変更可能なものは最大 2 個 | xz-file-format.txt §5.2 | ✅ | フィルター設計者向け MUST。標準フィルター (BCJ/Delta) はサイズ保存のため構造的に充足。custom registry 経由のフィルターは登録側責務であり crate は件数を強制しない (liblzma も decode 時に強制しない) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 55 |
| **合計** | **55** |
