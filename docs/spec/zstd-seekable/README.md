# Zstandard Seekable Format

| 項目 | 内容 |
|------|------|
| 形式概要 | 入力を複数の独立 zstd フレームに分割し、末尾に seek table を zstd skippable frame (magic `0x184D2A5E`) として付加する形式。任意の zstd デコーダで通常の multi-frame zstd として復号できる一方、seek table を解釈するデコーダは範囲伸張が可能 |
| 基準仕様 | [Zstandard Seekable Format](https://github.com/facebook/zstd/tree/dev/contrib/seekable_format) v0.1.0 (ローカルスナップショット: `docs/spec/sources/zstd_seekable_compression_format.md`) |
| 実装 | `archive::compress::zstd::seekable` (encode / decode / decode_range / seek_table / has_seek_table)。`zstd` feature 配下 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| seek table あり (Checksum_Flag=0) | format doc §Seek Table Format | ✅ | ✅ | エンコーダ出力 |
| seek table あり (Checksum_Flag=1) | format doc §Seek_Table_Descriptor / §Checksum | ✅ | ✅ | `encode_with_checksums` が flag=1 で出力 |
| seek table なし (plain multi-frame zstd) | zstd 本体 | ✅※ | — | ※ `compress::zstd::decode` で復号可能。`seekable::decode` は seek table 必須として拒否 |

## Seek Table 構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | seek table は skippable frame (magic `0x184D2A5E`) 内に配置 | format doc §Seek Table Format | ✅ | `test_zstd_seekable_decode_reference_text` (統合) |
| 2 | `Frame_Size` は entries + footer のバイト数と一致 (magic/size フィールドを含まない) | format doc §Frame_Size | ✅ | `rejects_bad_frame_size` |
| 3 | footer 構造: `Number_Of_Frames` (u32 LE) + `Seek_Table_Descriptor` (u8) + `Seekable_Magic_Number` `0x8F92EAB1` (u32 LE)。マジックはファイル末尾必須 | format doc §Seek_Table_Footer | ✅ | `has_seek_table`、全 decode テスト |
| 4 | 各 entry は `Compressed_Size` (u32) + `Decompressed_Size` (u32) (+ `Checksum` u32、flag 時) | format doc §Seek_Table_Entries | ✅ | `test_zstd_seekable_decode_reference_*` (統合) |
| 5 | `Compressed_Size` の累積和は seek table 直前までの全フレーム領域と一致 | format doc §Compressed_Size | ✅ | `rejects_wrong_cumulative_size` |
| 6 | `Checksum_Flag` (descriptor bit 7) 設定時、entry 末尾に伸張データの XXH64 下位 32bit (LE) | format doc §Checksum_Flag / §Checksum | ✅ | `decode_checksum_flag_stream`、参照ベクタ (flag=1) |
| 7 | `Reserved_Bits` (bit 6-2) は 0 必須、非0 は拒否 | format doc §Reserved_Bits | ✅ | `rejects_reserved_bits` |
| 8 | `Unused_Bits` (bit 1-0) は解釈しない | format doc §Unused_Bits | ✅ | decoder が無視 (テスト間接) |

## 動作要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 9 | 各フレームは独立した zstd フレームとして復号可能 | format doc §Introduction | ✅ | `roundtrip_multi_frame` |
| 10 | `decode` は seek table 必須。なしは `InvalidData` で拒否 | crate contract (format 名の厳密性) | ✅ | `plain_zstd_stream_rejected`、`test_zstd_seekable_rejects_plain_zstd` (統合) |
| 11 | `decode_range` は範囲に重なるフレームのみ復号 | format doc §Introduction (設計目的) | ✅ | `range_decode_within_frame`、`range_decode_across_frames`、`test_zstd_seekable_range_reference` (統合) |
| 12 | 各 entry の `Decompressed_Size` / `Checksum` を復号結果と照合 | format doc §Seek_Table_Entries | ✅ | `decode_checksum_flag_corrupted` |
| 13 | skippable/空フレームは `Decompressed_Size = 0` | format doc §Decompressed_Size | ✅ | 参照ベクタ経由で間接検証 |
| 14 | seekable ストリームは通常の zstd デコーダでも復号可能 (skippable frame 互換) | format doc §Introduction / RFC 8878 §3.1.1 | ✅ | `test_zstd_seekable_plain_zstd_decodes` (統合) |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | footer magic 不在 (非 seekable 入力) の拒否 | format doc §Seekable_Magic_Number | ✅ | `plain_zstd_stream_rejected` |
| 16 | 切り詰め seek table / skippable magic 不正の拒否 | format doc | ✅ | `rejects_truncated_table`、`rejects_bad_frame_size` |
| 17 | `Compressed_Size = 0` の entry 拒否 | crate contract (実フレームは 0 バイトになり得ない) | ✅ | `seek_table` 内検証 |
| 18 | footer 後の余剰バイトの拒否 (マジックが末尾必須) | format doc §Seekable_Magic_Number | ✅ | `trailing_garbage_after_footer_rejected` |
| 19 | `decode_range` の範囲外アクセス拒否 | crate contract | ✅ | `range_decode_out_of_bounds` |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 20 | 入力を `frame_size` ごとの独立フレームに分割して seek table を生成 | format doc | ✅ | `roundtrip_multi_frame`、`test_zstd_seekable_roundtrip` (統合) |
| 21 | 空入力は 0 フレーム + seek table のみを出力 | format doc (`Number_Of_Frames=0`) | ✅ | `roundtrip_empty` |
| 22 | `encode` は `Checksum_Flag=0`、`encode_with_checksums` は flag=1 (XXH64 下位32bit 付加) の seek table を出力 | format doc §Checksum_Flag / §Checksum | ✅ | `encode_checksum_flag_stream`、参照ツール interop (両出力を復号検証)

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 23 | CLI `--format zstd-seekable` で decode/encode (自動検出は `zstd` として扱う) | crate CLI contract | ✅ | archive-cli 配線 |

## 出典 / 検証メモ

- 仕様書は Meta の `contrib/seekable_format/zstd_seekable_compression_format.md` v0.1.0 (再配布許可型の copyright notice)。本実装は当該文書から独立実装したもので、参照 C 実装 (`zstdseek_compress.c` / `zstdseek_decompress.c`, BSD/GPL dual) のコード移植は行っていない。
- 統合テストの `tests/fixtures/zstd/seekable_*.zst` は参照ツール (`contrib/seekable_format/examples/seekable_compression`, zstd git dev 版) をローカルでビルドして生成した既知解答ベクタ。`Checksum_Flag=1` を含む。range decode も参照ツール (`seekable_decompression_mem`) の出力と照合済み。
- 本形式はコンテナではなく zstd フレーム列 + 末尾 seek table の構成のため、`zstd` feature のサブモジュールとして実装している (独立 feature ではない)。
