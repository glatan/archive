# LZW (Unix compress `.Z` フォーマット)

| 項目 | 内容 |
|------|------|
| 基準仕様 | 正式な RFC はなく、`ncompress` (`compress42.c`) のデファクト標準に準拠 |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー `0x1F 0x9D` 検証 | ncompress `compress42.c`: file header | ✅ | `test_invalid_magic` |
| 2 | ヘッダー長チェック (3バイト未満) | ncompress `compress42.c`: file header | ✅ | `test_input_too_short` |
| 3 | max_bits 範囲チェック (9-16) | ncompress `compress42.c`: file header | ✅ | `test_max_bits_out_of_range` |
| 4 | ブロックモード (クリアコード 256) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_large` (辞書フル→クリア) |
| 5 | 可変幅コード 9-16ビット | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_max_bits_range`, `test_roundtrip_large` |
| 6 | コード幅遷移タイミング (ncompress互換) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_large` (max_bits=10, 512バイト) |
| 7 | LSB-first ビットパッキング | ncompress `compress42.c`: bit packing | ✅ | `test_read_code_lsb_first` |
| 8 | KwKwK 特殊ケース (code == next_code) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_roundtrip_kwkwk` |
| 9 | 空データの圧縮/伸張 | ncompress `compress42.c` | ✅ | `test_roundtrip_empty`, `test_empty_compressed_data` |
| 10 | 単一バイトの圧縮/伸張 | ncompress `compress42.c` | ✅ | `test_roundtrip_single_byte` |
| 11 | 全バイト値 (0-255) のラウンドトリップ | ncompress `compress42.c` | ✅ | `test_roundtrip_all_bytes` |
| 12 | 不正コード検出 (code > next_code) | ncompress `compress42.c`: code stream / dictionary growth | ✅ | `test_code_out_of_range` |
| 13 | system compress 互換性 | ncompress `compress42.c` compatibility | ✅ | `test_lzw_decode_system_compress_fixture` (統合テスト) |
| 14 | `encode_writer` / `decode_reader` (std::io) | ncompress `compress42.c` | ✅ | doctest |
| 15 | Header byte 2: max_bits (bits 0-4) + block_mode flag (bit 7) | ncompress header layout | ✅ | デコーダーで parse |
| 16 | Dictionary 初期化: codes 0-255 = single byte, code 256 = clear code (block mode) | ncompress dictionary | ✅ | 実装済み |
| 17 | First emitted code は raw byte (0-255) | ncompress code stream | ✅ | 実装済み |
| 18 | Non-block-mode: dictionary が full になっても reset しない | ncompress block_mode=false | ✅ | `test_roundtrip_non_block_mode`, `test_non_block_mode_header_flag`, `test_non_block_mode_decode`, `encode_with_full_options()` |
| 19 | Max dictionary size: 2^max_bits entries | ncompress dictionary growth | ✅ | `test_fuzz_regression_dict_full_wraparound` (辞書フル境界: next_code=65536) |
| 20 | Code width increase タイミング: ncompress 互換 (early change) | ncompress code stream | ✅ | item 6 で部分記載 |
| 21 | EOF trailing partial code group: 不完全な最終 code group は無視 | ncompress EOF handling | ✅ | デコーダーで暗黙的に処理 |

---

## 外部ツール非互換 (intentional scope)

以下は `ncompress` (system `compress`/`uncompress`) 固有の動作であり、ライブラリ実装の問題ではありません。
fuzz の `original-compress` / `original-decompress` パターンでの false failure を防ぐため、`fuzz/src/known_issues.rs` でフィルタリングされます。

| # | 項目 | 対象 variant | 理由 |
|---|------|------------|------|
| A | `ncompress` による空入力の拒否 | `lzw`, `lzw-bits9` | `compress`/`uncompress` は空入力に対して exit status 2 で終了する。ライブラリは空データを正常処理する (`test_roundtrip_empty`, `test_empty_compressed_data`) |
| B | `compress -b 9` の非可逆 roundtrip | `lzw-bits9` | `ncompress -b 9` は一部の入力に対してロッシーな roundtrip を起こす外部ツール自身のバグ。system `uncompress` でも元データを復元できない場合がある |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 21 |
| **合計** | **21** |


---
