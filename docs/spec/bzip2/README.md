# bzip2 (リファレンス実装 bzip2 1.0.x 準拠)

| 項目 | 内容 |
|------|------|
| 基準仕様 | Julian Seward 作の [bzip2](https://www.sourceware.org/bzip2/) リファレンス実装 (1.0.x) と[付属マニュアル](https://www.sourceware.org/bzip2/manual/manual.html)、およびソースコード (`compress.c`, `decompress.c`, `huffman.c`, `bzlib.h`) をデファクト仕様として扱う。補助: [BZIP2 Format Specification (Joe Tsai)](https://raw.githubusercontent.com/dsnet/compress/master/doc/bzip2-format.pdf) (bzip2-1.0.6 からの非公式逆解析文書、ローカルスナップショット: `docs/spec/sources/bzip2-format_dsnet.pdf`) |

### ストリームフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | ストリームヘッダー `BZh[1-9]` (マジック + ブロックサイズ) | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `test_invalid_magic`, `test_invalid_block_size`, `test_truncated_header` |
| 2 | ブロックマジック `0x314159265359` (π の16進表現, 48bit) | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `decode_block()` で検証 |
| 3 | ストリームトレーラーマジック `0x177245385090` (√π の16進表現, 48bit) | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `decode()` で検証 |
| 4 | ストリーム CRC (combined_crc = rotate_left(1) ^ block_crc) | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `decode()` でストアCRCと照合 |
| 5 | ブロック CRC-32 (big-endian, 非反射型 polynomial 0x04C11DB7) | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `test_bz2_crc32_single_x`, `test_bz2_crc32_empty`, `test_bz2_crc32_incremental` |
| 6 | CRC-32 初期値 0xFFFFFFFF / 最終 XOR 0xFFFFFFFF | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `Bz2Crc32::new/finish` |
| 7 | ブロック CRC は原データ (pre-RLE1) に対して計算 | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `encode_block()` / `decode_block()` で検証 |
| 8 | 空ストリーム (ヘッダー + トレーラーのみ、ブロックなし) | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `test_decode_empty_stream` |
| 9 | マルチブロックストリーム | bzip2 1.0.x manual / `bzlib.h` stream format | ✅ | `test_roundtrip_multi_block`, `test_roundtrip_multi_block_with_runs`, 統合テスト |

### ブロック構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 10 | ランダマイズドフラグ (1bit) — 旧バージョン互換 | `compress.c` / `decompress.c` block header and selector format | ✅ | `test_decode_randomized_block_fixture`, `test_randomization_helper_roundtrip` |
| 11 | オリジナルポインタ (BWT ptr, 24bit) | `compress.c` / `decompress.c` block header and selector format | ✅ | デコーダで範囲検証 |
| 12 | 二段シンボルビットマップ (16bit グループマスク + 16bit/グループ) | `compress.c` / `decompress.c` block header and selector format | ✅ | `test_parse_symbol_map`, `test_symbol_map_roundtrip` |
| 13 | n_in_use = 0 のエラー | `compress.c` / `decompress.c` block header and selector format | ✅ | デコーダ `decode.rs:193` |
| 14 | ハフマンテーブル数 (3bit, 有効値 2-6) | `compress.c` / `decompress.c` block header and selector format | ✅ | デコーダで `2..=6` バリデーション |
| 15 | セレクタ数 (15bit) | `compress.c` / `decompress.c` block header and selector format | ✅ | `test_invalid_selector_count` |
| 16 | セレクタ上限 MAX_SELECTORS = 18002 (2 + 900000/50) | `compress.c` / `decompress.c` block header and selector format | ✅ | `test_invalid_selector_count` |
| 17 | セレクタ: ユーナリ符号 → MTF デコード | `compress.c` / `decompress.c` block header and selector format | ✅ | `write_selectors` / `parse_selectors` ラウンドトリップ |
| 18 | セレクタインデックス範囲検証 (< num_tables) | `compress.c` / `decompress.c` block header and selector format | ✅ | `parse_selectors` (decode.rs:311 付近) |
| 19 | ブロックサイズ上限 (blockSize100k * 100000) | `compress.c` / `decompress.c` block header and selector format | ✅ | デコーダで `undo_mtf_rle2` 内の出力サイズ制限 |
| 20 | ブロックサイズのRLE1出力基準 (-19バイトヘッドルーム) | `compress.c` / `decompress.c` block header and selector format | ✅ | `encode_with_level` (encode.rs:107-111) |

### RLE1 (Run-Length Encoding 第1段)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 21 | 4バイト同一 + カウントバイト (0-255) → 合計 4~259 バイトのラン | `compress.c` / `decompress.c` RLE1 stage | ✅ | `test_rle1_run_of_4/5`, `test_rle1_long_run` |
| 22 | 3バイト以下の同一はそのまま通過 | `compress.c` / `decompress.c` RLE1 stage | ✅ | `test_rle1_run_of_3_no_encoding`, `test_rle1_no_runs` |
| 23 | ラン長上限 259 (4 + 255) | `compress.c` / `decompress.c` RLE1 stage | ✅ | `test_rle1_long_run`, `test_roundtrip_max_rle1_run` |
| 24 | デコーダ: カウントバイト欠損エラー | `compress.c` / `decompress.c` RLE1 stage | ✅ | デコーダ `undo_rle1` (decode.rs:455-458) |
| 25 | ブロック分割はRLE1出力サイズ基準 | `compress.c` / `decompress.c` RLE1 stage | ✅ | `test_roundtrip_multi_block_with_runs`, `test_apply_rle1_bounded` |

### BWT (Burrows-Wheeler 変換)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 26 | 前方 BWT: 接尾辞配列 (prefix-doubling) によるソート | `blocksort.c` / `decompress.c` BWT logic | ✅ | `test_roundtrip_banana/hello/all_bytes` (bwt) |
| 27 | 逆 BWT: LF-mapping による復元 | `blocksort.c` / `decompress.c` BWT logic | ✅ | `test_roundtrip_banana/hello/all_bytes` (bwt) |
| 28 | 空入力 | `blocksort.c` / `decompress.c` BWT logic | ✅ | `test_roundtrip_empty` (bwt) |
| 29 | 全バイト同一入力 | `blocksort.c` / `decompress.c` BWT logic | ✅ | `test_roundtrip_all_same` (bwt) |
| 30 | original_ptr 範囲検証 | `blocksort.c` / `decompress.c` BWT logic | ✅ | デコーダ (decode.rs:239、`orig_ptr >= bwt_data.len()` を検証) |

### MTF + RLE2 (Move-To-Front + 零ラン符号化)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 31 | MTF リスト初期化 (0..n_in_use) | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `apply_mtf_rle2` / `undo_mtf_rle2` |
| 32 | n_in_use=256 時の MTF リスト構築 (u8 オーバーフロー対策) | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `test_roundtrip_all_bytes` |
| 33 | RUNA(0) / RUNB(1) bijective base-2 符号化 | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `test_zero_run_encoding`, `test_zero_run_encoding_values` |
| 34 | MTF インデックス +1 シフト (RUNA/RUNB と衝突回避) | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `test_undo_mtf_rle2_simple` |
| 35 | EOB シンボル = n_in_use + 1 | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `decode_symbols` / `encode_block` |
| 36 | MTF インデックス範囲外エラー | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `test_undo_mtf_rle2_invalid_index` |
| 37 | 零ランのブロックサイズ超過検出 (メモリ枯渇対策) | `compress.c` / `decompress.c` MTF + RUNA/RUNB stage | ✅ | `test_undo_mtf_rle2_run_exceeds_block_size` |

### ハフマン符号化

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 38 | MSB-first (big-endian) ビット順序 | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `test_roundtrip_bits`, `test_48bit_magic` (bitstream) |
| 39 | 正準ハフマンコード構築 | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `test_huffman_roundtrip` |
| 40 | コード長 1-20 (MAX_CODE_LEN=20) | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `test_code_length_exceeds_20`, `test_build_huffman_table` |
| 41 | デルタ符号化テーブル (5bit 開始値 + 増減デルタ) | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `test_parse_write_huffman_tables` |
| 42 | デルタ方向: 1=減、0=増 | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `parse_huffman_tables` / `write_huffman_tables` ラウンドトリップ |
| 43 | テーブル切替 (GROUP_SIZE=50 シンボル毎) | `huffman.c` / `compress.c` / `decompress.c` | ✅ | ラウンドトリップテストで検証 |
| 44 | 反復的テーブル最適化 (4回) | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `build_tables_and_selectors` (参照実装と同じ4回) |
| 45 | Kraft 不等式を満たすコード長制限 (enforce_max_code_length) | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `test_enforce_max_code_length` |
| 46 | 均一コード長 (min_len == max_len) | `huffman.c` / `compress.c` / `decompress.c` | ✅ | `test_huffman_uniform_lengths` |

### ビットストリーム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 47 | MSB-first ビット読み取り/書き込み (1-32bit) | `compress.c` / `decompress.c` bitstream IO | ✅ | `test_roundtrip_bits` |
| 48 | 48bit 読み取り/書き込み (マジックナンバー用) | `compress.c` / `decompress.c` bitstream IO | ✅ | `test_48bit_magic` |
| 49 | u8/u32 読み取り/書き込み | `compress.c` / `decompress.c` bitstream IO | ✅ | `test_write_u32` |
| 50 | EOF エラー | `compress.c` / `decompress.c` bitstream IO | ✅ | `test_read_eof` |
| 51 | 最終バイトのゼロパディング | `compress.c` / `decompress.c` bitstream IO | ✅ | `BitWriter::finish` |

### エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 52 | レベル 1-9 (ブロックサイズ 100KB-900KB) | `compress.c` | ✅ | `test_roundtrip_level_1`, `test_level_clamping` |
| 53 | レベル範囲外のクランプ (0→1, 10→9) | `compress.c` | ✅ | `test_level_clamping` |
| 54 | テーブル数自動選択 (シンボル数基準: 200/600/1200/2400) | `compress.c` | ✅ | `test_select_num_tables` |
| 55 | 空入力エンコード | `compress.c` | ✅ | `test_roundtrip_empty` |
| 56 | 全バイト値 (0-255) ラウンドトリップ | `compress.c` | ✅ | `test_roundtrip_all_bytes` |
| 57 | バイナリデータラウンドトリップ | `compress.c` | ✅ | `test_roundtrip_binary_data` |
| 58 | 長ランラウンドトリップ | `compress.c` | ✅ | `test_roundtrip_long_runs`, `test_roundtrip_max_rle1_run` |
| 59 | ブロック境界でのラン分割 | `compress.c` | ✅ | `test_roundtrip_block_boundary_run` |
| 60 | 単一バイト大量入力 (全零 100KB) | `compress.c` | ✅ | `test_roundtrip_single_byte_large` |
| 61 | encode_writer (std::io::Write 対応) | `compress.c` | ✅ | doctest |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 62 | system bzip2 で圧縮したデータのデコード | bzip2 1.0.x reference implementation behavior | ✅ | `test_decode_system_bzip2`, `test_bzip2_decode_system_compressed` (統合) |
| 63 | system bzip2 -d での展開互換 | bzip2 1.0.x reference implementation behavior | ✅ | `test_bzip2_encode_decoded_by_system` (統合、system bzip2 呼び出し) |
| 64 | 大規模データ (100KB+) の system 互換 | bzip2 1.0.x reference implementation behavior | ✅ | `test_bzip2_large_interop_with_system` (統合) |
| 65 | マルチブロック (200KB level 1) の system 互換 | bzip2 1.0.x reference implementation behavior | ✅ | `test_bzip2_roundtrip_multi_block` (統合) |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 66 | Concatenated .bz2 streams (stream-after-stream) | bzip2 reference behavior | ✅ | `test_decode_concatenated_streams`, `test_decode_concatenated_three_streams` |
| 67 | Padding bits after stream trailer (最大 7 bits) の無視 | bzip2 reference behavior | ✅ | BitReader で処理 |
| 68 | original_ptr >= block_data_length rejection | bzip2 reference: BWT | ✅ | デコーダーで range 検証 |
| 69 | NumSels: セレクタ枯渇時は decoder がエラー | bzip2-format §2.2.3.2 | ✅ | `decode.rs:346-347` "ran out of selectors" |
| 70 | 非完全 (over/under-subscribed) Huffman 木の扱い | bzip2-format §2.2.3.2.3 + Appendix B | ✅ | canonical decode で `len > max_len` 時に `invalid bzip2 Huffman code` を返す (under-subscribed はエラー)。C 実装互換 decoder は無効シンボル使用時にのみエラーという記述に対し、本実装は厳格側 |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 70 |
| **合計** | **70** |

