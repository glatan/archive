# LZO (LZO1X-1 + lzop ファイルフォーマット)

| 項目 | 内容 |
|------|------|
| LZO1X 基準仕様 | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) (ローカルスナップショット: `docs/spec/sources/linux_lzo.rst`) |
| lzop 基準仕様 | [lzop](https://www.lzop.org/) ソースコード (`lzop.h` / `p_lzo.c`) をデファクト仕様として扱う |
| 参照実装 | lzop (Markus Oberhumer、GPL-2.0-or-later、format facts のみの動作参照 — コード取り込みなし。GPL-2.0+→GPL-3→AGPL-13 の変換パスあり + fixture 生成: `tests/fixtures/lzo/hello.lzo` + oracle)。詳細: THIRD_PARTY_NOTICES LZO / lzop 項 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| LZO1X バイトコード | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | ✅ | |
| lzop コンテナ | lzop ソース (`lzop.h`/`p_lzo.c`) | ✅ | ✅ | |

### LZO1X バイトコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | M2 マッチ (offset 1-2048, len 3-8, 2バイト命令) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_repeated`, `test_roundtrip_english_text` |
| 2 | M3 マッチ (offset 1-16384, len 3+, 3バイト命令) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_large` (大データで長距離マッチ発生) |
| 3 | M4 マッチ (offset 16385-49151, len 3+, 3バイト命令) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_m4_max_offset_roundtrip` |
| 4 | M1 短マッチ (state>0, offset 1-2048, len 2) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_m1_short_match_state_1_to_3` |
| 5 | S ビット (LE16 下位2ビット: 後続リテラル数) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | デコーダーで M2/M3/M4 すべてで S ビット抽出 |
| 6 | VLE (可変長エンコーディング: 0バイト×255 + 非零バイト) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_large` (18超リテラルで VLE 使用), `test_lzo_vle_255_boundary`, `test_write_vle_boundary_values` |
| 7 | State=0 リテラルラン (byte 1-15 → count=byte+3) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_short`, `test_roundtrip_all_bytes` |
| 8 | State=0 拡張リテラルラン (byte 0 → count=18+VLE) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_all_bytes` (256バイト) |
| 9 | End-of-stream マーカー (M4, offset=16384, len=3) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_repeated`, 全ラウンドトリップテスト |
| 10 | 先頭リテラルラン (byte > 17 → t-17 リテラル) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_initial_literal_run_byte_gt_17` |

### lzop ファイルフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | マジックナンバー (89 4C 5A 4F 00 0D 0A 1A 0A) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_lzop_header`, `test_invalid_magic` |
| 12 | ヘッダーフィールド (version, lib_version, version_needed, method, level) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_lzop_header` |
| 13 | フラグフィールド (F_ADLER32_D 等) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | エンコーダーで F_ADLER32_D 設定、デコーダーで検証 |
| 14 | ヘッダー Adler-32 チェックサム | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_roundtrip_hello`, ヘッダーチェックサム不一致エラー検出 |
| 15 | ブロック構造 (uncompressed_len + compressed_len + checksum + data) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | 全ラウンドトリップテスト |
| 16 | 非圧縮ブロック (compressed_len == uncompressed_len) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_roundtrip_short` (短データは非圧縮格納) |
| 17 | 256KB ブロック分割 | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_roundtrip_multi_block` |
| 18 | Adler-32 データチェックサム検証 | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | デコーダーでブロック毎に検証 |
| 19 | Adler-32 圧縮データチェックサム検証 (`F_ADLER32_C`) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_adler32_compressed_verified` |
| 20 | 終端マーカー (uncompressed_len=0) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_empty_input` |
| 21 | 不正マジックエラー | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_invalid_magic` |
| 22 | 入力短すぎエラー | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_input_too_short` |
| 23 | CRC-32 compressed data checksum verification | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_crc32_compressed_verified_direct` |
| 24 | CRC-32 uncompressed data checksum verification | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_crc32_uncompressed_verified_direct` |
| 25 | Compression method validation (1/2/3 only) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_method_validation_rejected` |
| 26 | version_needed validation (<= 0x1040) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_version_needed_too_new_rejected` |
| 27 | F_H_EXTRA flag handling | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_header_extra_field_handled` |
| 28 | F_H_FILTER flag handling (skip) | lzop source (`lzop.h`, `p_lzo.c`) | ✅ | `test_header_filter_field_handled` |

### エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 29 | ハッシュテーブルベースのマッチ検索 (14ビットハッシュ) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_roundtrip_repeated` |
| 30 | リテラルラン間隔制約 (0 or ≥4 バイト) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | `test_gap_below_four_is_skipped` |
| 31 | 末尾リテラル保護 (LAST_LITERALS=5) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | 全ラウンドトリップテスト |
| 32 | encode_writer (std::io::Write 対応) | [Linux kernel `Documentation/staging/lzo.rst`](https://docs.kernel.org/staging/lzo.html) | ✅ | doctest |

### システム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 33 | システム lzop 生成データのデコード | lzop interoperability behavior | ✅ | `test_lzo_decode_system_fixture` |
| 34 | 当ライブラリ出力をシステム lzop でデコード | lzop interoperability behavior | ✅ | `test_lzo_encode_decoded_by_system` |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 35 | Lookback window size: ~49KB (M4 max offset 49151) | Linux kernel lzo.rst | ✅ | M4 offset 制限で暗黙的 |
| 36 | lzop header: mtime_low / mtime_high fields | lzop source | ✅ | ヘッダーでパース |
| 37 | lzop header: optional name field (name_length + name bytes) | lzop source | ✅ | ヘッダーでパース |
| 38 | F_CRC32_D / F_CRC32_C と F_ADLER32_D / F_ADLER32_C は排他 | lzop source | ✅ | デコーダーで対応 |
| 39 | Decompressed output size 検証 (uncompressed_len と一致) | lzop block structure | ✅ | デコーダーで検証 |
| 40 | 命令形式 `0 0 0 0 D D S S` の state==4 形式 (offset 2049-3072, len 3) | Linux kernel lzo.rst: Instruction encoding | ✅ | `decode.rs:423-439` で実装 |
| 41 | lzop `version < 0x0940` の拒否 | lzop source | ✅ | `decode.rs:77`、`test_old_version_rejected` |
| 42 | bitstream version byte 17 (v1 / LZO-RLE) と v1 専用ゼロラン命令 | Linux kernel lzo.rst | ✅ | 先頭 17 + version byte (0/1) の versioned bitstream を受理 (version > 1 は `Error::Unsupported`)。v1 では M4 distance 0xbfff のゼロラン命令 (LZO-RLE) を decode。5 バイト未満の入力は先頭 17 を v0 命令バイトとして解釈。`test_v1_bitstream_version_byte`, `test_v1_zero_run_decode`, `test_v1_bitstream_short_stream_is_v0` |


---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 42 |
| **合計** | **42** |
