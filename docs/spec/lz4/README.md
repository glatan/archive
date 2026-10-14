# LZ4 (LZ4 フレームフォーマット)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [LZ4 Frame Format spec 1.6.2](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Frame_format.md) / [LZ4 Block Format spec 1.3.1](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) (lz4 v1.9.4 `doc/` ピン留め、ローカルスナップショット: `docs/spec/sources/lz4_frame_format_1.6.2.md` / `lz4_block_format_1.3.1.md`) |
| 参照実装 | liblz4 `lz4.c`/`lz4frame.c` (BSD-2-Clause、legacy frame 詳細の動作参照のみ、コード取り込みなし)。system `lz4` (liblz4 BSD-2-Clause / CLI GPL-2.0) はテスト時の oracle および `tests/fixtures/lz4/hello.lz4` の fixture 生成にのみ使用 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| frame format | [LZ4 Frame Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Frame_format.md) | ✅ | ✅ | magic `0x184D2204`、xxhash32 チェックサム |
| raw block format | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | ✅ | frame なし raw block API |

### フレームフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `0x184D2204` (LE) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_header_format`, `test_invalid_magic` |
| 2 | FLG バイト: version=01 (bits 7-6) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_header_format` |
| 3 | FLG バイト: Block_Independence フラグ (bit 5) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_header_format` |
| 4 | FLG バイト: Content_Size フラグ (bit 3) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_header_format`, デコーダーで検証 |
| 5 | FLG バイト: Content_Checksum フラグ (bit 2) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_header_format`, デコーダーで検証 |
| 6 | FLG バイト: Block_Checksum フラグ (bit 4) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_block_checksum_present_for_uncompressed_block`, `test_block_checksum_mismatch` |
| 7 | FLG バイト: Dictionary_ID フラグ (bit 0) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_dict_id_flag_rejected`, `test_encode_with_dict_sets_dict_id_flag` |
| 8 | BD バイト: Block_MaxSize (bits 6-4) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_roundtrip_with_block_sizes` |
| 9 | Content_Size (8バイト LE、オプション) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | エンコーダーで常に出力、デコーダーで検証 |
| 10 | Header_Checksum (xxhash32 の 2バイト目) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_header_checksum_mismatch` |
| 11 | ブロックサイズ bit 31 = 非圧縮フラグ | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_uncompressed_fallback` |
| 12 | EndMark (`0x00000000`) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_empty_input`、`test_decode_truncated_at_every_position` (全切断位置で拒否) |
| 13 | Content_Checksum (xxhash32、オプション) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_content_checksum_mismatch` |
| 14 | Block_Checksum (xxhash32、オプション) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_block_checksum_present_for_uncompressed_block`, `test_block_checksum_mismatch` |
| 15 | 不正バージョンエラー | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_rejects_invalid_flg_version` (FLG version != 01 は HC 検証より先に `InvalidData`) |
| 16 | 入力短すぎエラー | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_input_too_short` |
| 17 | Skippable Frame (0x184D2A50-5F) support | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_skippable_frame_decode` |
| 18 | FLG reserved bits (bit 1) validation | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_flg_reserved_bit1_rejected` |
| 19 | BD reserved bits validation | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_bd_reserved_bits_rejected` |
| 20 | Block max size ID >= 4 validation | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_block_max_size_id_below_4_rejected` |
| 21 | Block-dependent mode decode (FLG bit 5=0) | LZ4 Frame Format: Frame Descriptor / Data Blocks / EndMark | ✅ | `test_decode_block_dependent_frame` |

### ブロックフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | トークンバイト: リテラル長 (上位4bit) + マッチ長 (下位4bit) | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | ラウンドトリップで検証 |
| 23 | LSIC (Linear Small Integer Code) リテラル長拡張 | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | 長いデータのラウンドトリップ |
| 24 | リテラルコピー | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | 全ラウンドトリップテスト |
| 25 | マッチオフセット (2バイト LE) | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | ラウンドトリップで検証、`test_decode_max_match_offset_65535` |
| 26 | LSIC マッチ長拡張 | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | 長いデータのラウンドトリップ |
| 27 | 最小マッチ長 4 | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `MIN_MATCH` 定数、ラウンドトリップ |
| 28 | 最終シーケンスはマッチなし | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `emit_literals` |
| 29 | 重複コピー (offset < match_len) | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `test_overlap_copy` |
| 30 | マッチオフセット 0 エラー | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `test_decode_block_malformed` (offset=0 を含む) |
| 31 | マッチオフセット超過エラー | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | デコーダーで検証 |
| 32 | 辞書 prefix 参照マッチ | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `test_decode_with_dict_roundtrip`, `test_encode_with_dict_roundtrip` |
| 33 | Last-5-literals 制約 | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `LAST_LITERALS=5`、エンコーダーで適用 |
| 34 | MF_LIMIT (12バイト) 制約 | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `MF_LIMIT=12`、エンコーダーで適用 |
| 34a | Raw block decode API (frame なし、max_output 上限) | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `decode_block()` / `decode_block_with_dict()`、`test_decode_block_roundtrip`、`test_decode_block_limit_exceeded` |
| 34b | Raw block encode API (frame なし、辞書 prefix 対応) | [LZ4 Block Format](https://raw.githubusercontent.com/lz4/lz4/v1.9.4/doc/lz4_Block_format.md) | ✅ | `encode_block()` / `encode_block_with_dict()`、`test_decode_block_roundtrip_with_dict` |

### ブロックサイズ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 35 | 64KB ブロック | LZ4 Frame Format: BD / Block Maximum Size | ✅ | `test_roundtrip_with_block_sizes` |
| 36 | 256KB ブロック | LZ4 Frame Format: BD / Block Maximum Size | ✅ | `test_roundtrip_with_block_sizes` |
| 37 | 1MB ブロック | LZ4 Frame Format: BD / Block Maximum Size | ✅ | `test_roundtrip_with_block_sizes` |
| 38 | 4MB ブロック (デフォルト) | LZ4 Frame Format: BD / Block Maximum Size | ✅ | `test_roundtrip_with_block_sizes`, デフォルトエンコード |

### ラウンドトリップ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 39 | 空データ | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_empty` |
| 40 | 単一バイト | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_single_byte` |
| 41 | 短いデータ | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_hello` |
| 42 | 繰り返しデータ | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_repeated` |
| 43 | 全バイト値 (0-255) | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_all_bytes` |
| 44 | 大規模データ (100KB) | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_large` |
| 45 | 英語テキスト (圧縮効果検証) | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_roundtrip_english_text` |
| 46 | 辞書付きラウンドトリップ | LZ4 Frame Format + LZ4 Block Format | ✅ | `test_decode_with_dict_roundtrip`, `test_encode_with_dict_roundtrip` |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 47 | system lz4 で圧縮したデータのデコード | LZ4 Frame Format compatibility | ✅ | `test_lz4_decode_system_fixture` (統合) |
| 48 | system lz4 -d での展開互換 | LZ4 Frame Format compatibility | ✅ | `test_lz4_encode_decoded_by_system` (統合) |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 49 | Legacy frame format (magic 0x184C2102)。legacy ブロックは 8MB 固定・最終ブロック以外は全埋め | LZ4 Legacy Frame | ✅ | `LEGACY_MAGIC` 定数、decode: `decode_legacy_frame()`、encode: `encode_legacy()` (`LEGACY_BLOCK_SIZE = 8MB` で chunked)。leniency: `block_size == 0` も終端として受理する (legacy format の正式な終端は EOF または次 magic のみ)。展開上限なし (`usize::MAX`) で `decode_bounded` による事後制限は可能 |
| 50 | Content_Size mismatch error (decode 時に検証) | LZ4 Frame: Content_Size | ✅ | デコーダーで検証 |
| 51 | Block decompressed size ≤ Block_MaxSize 検証 | LZ4 Frame: Data Blocks | ✅ | 実装済み — `decompress_block` の `max_output` に Block_MaxSize を適用、展開超過は `Error::InvalidData`。`test_block_decompressed_size_exceeds_max_rejected` `test_block_size_at_max_accepted` |
| 52 | Block_MaxSize ID → size mapping: 4=64KB, 5=256KB, 6=1MB, 7=4MB | LZ4 Frame: BD | ✅ | 実装済み |
| 53 | Header checksum algorithm: (xxhash32 >> 8) & 0xFF | LZ4 Frame: HC | ✅ | 実装済み |
| 54 | Multi-frame (concatenated frames) | LZ4 Frame | ✅ | `test_multi_frame_standard_concat`, `test_multi_frame_legacy_then_standard`, `test_multi_frame_standard_then_legacy`, `test_multi_frame_three_legacy` |
| 55 | Block-dependent mode: encode | LZ4 Frame: FLG | ✅ | `encode_block_dependent()`, `test_block_dependent_header_flag`, `test_block_dependent_roundtrip`, `test_block_dependent_roundtrip_large`, `test_block_dependent_with_block_sizes` |
| 56 | Block_Size が Block_Maximum_Size を超えない | LZ4 Frame Format §Data Blocks | ✅ | 実装済み — ブロックループで宣言 Block_Size > Block_MaxSize を reject (圧縮/非圧縮共通、EOF チェックより前)。`test_block_size_exceeds_max_rejected` `test_uncompressed_block_size_exceeds_max_rejected` |
| 57 | `0x80000000` (bit31=1, size=0) は有効な空非圧縮ブロックで EndMark ではない | LZ4 Frame Format §Data Blocks | ✅ | 実装は `block_data_size==0` → 0 バイト extend で自然に受理 |
| 58 | streaming / bounded API と trailing garbage 方針 | crate contract | ✅ | `decode_reader`/`decode_bounded`/`encode_writer` 実装済み。trailing garbage: 残余 <4B は常に無視、非 magic な 4B 超の残余は output 非空のときのみ無視 (空 output なら `InvalidData`)。`encode_with_dict` に id なし dict を渡すと DictID flag なしで dict 依存 frame を生成する (decode 側は offset 範囲外エラーで検出 — silent corruption にはならない) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 60 |
| ❌ 未実装  | 0 |
| **合計** | **60** |


---
