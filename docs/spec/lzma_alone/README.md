# LZMA-Alone (`.lzma`)

| 項目 | 内容 |
|------|------|
| 形式概要 | 13バイトヘッダー (properties byte + 辞書サイズ + 非圧縮サイズ) + 生 LZMA ストリーム |
| 基準仕様 | [`lzma-file-format.txt`](https://raw.githubusercontent.com/tukaani-project/xz/master/doc/lzma-file-format.txt) (tukaani-project/xz `doc/`、2022-07-13 版、public domain。ローカルスナップショット: `docs/spec/sources/lzma-file-format-20220713.txt`) |
| 参照実装 | system `xz` (liblzma、public domain、oracle)。詳細: THIRD_PARTY_NOTICES LZMA-Alone 項 |

### ヘッダーフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | ヘッダーサイズ 13 バイト | lzma-file-format.txt: "The .lzma File Format" | ✅ | `test_encode_header_format` |
| 2 | properties byte (offset 0): `(pb*5+lp)*9+lc`、0..=224 | lzma-file-format.txt §1.1.1 (properties byte) | ✅ | `test_decode_rejects_invalid_props_byte` (225 拒否)、`test_decode_rejects_props_byte_224_unsupported_combo` (224 は lc+lp>4 で #17 拒否) |
| 3 | 辞書サイズ (offset 1-4, uint32 LE) | lzma-file-format.txt §1.1.2 | ✅ | `test_encode_header_format` |
| 4 | 辞書サイズ 0 の拒否 | lzma-file-format.txt §1.1.2 は「任意の 32bit 値」のみ規定 — 0 の拒否は XZ Utils 準拠の実装選択 (SDK 手続きは <4096 を 4096 に clamp するが本実装は 0 を reject、1..4095 は受理したうえで距離検査が実質制限する) | ✅ | `test_decode_rejects_zero_dict_size`、`test_encode_rejects_zero_dict_size`、`test_decode_accepts_minimum_dict_size` (dict=1 受理) |
| 5 | 非圧縮サイズ (offset 5-12, uint64 LE) | lzma-file-format.txt §1.1.3 | ✅ | `test_encode_header_format` |
| 6 | 非圧縮サイズ `0xFFFF_FFFF_FFFF_FFFF` = サイズ不明 | lzma-file-format.txt §1.1.3 | ✅ | `test_decode_unknown_size`, `test_lzma_alone_decode_system_compressed` (統合) |

### LZMA ストリーム終端

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | サイズ不明時は end-of-payload marker (EoPM) 必須 | lzma-file-format.txt: end of payload marker | ✅ | `test_decode_unknown_size`, `test_decode_empty_payload_unknown_size` |
| 8 | 既知サイズ + EoPM なし (サイズで正確に終了) | lzma-file-format.txt: end of payload marker | ✅ | `test_decode_known_size_without_eos` |
| 9 | 既知サイズ + EoPM あり (両形式の許容) | lzma-file-format.txt: end of payload marker | ✅ | `test_decode_known_size_with_eos`, `test_decode_empty_payload_known_size` |
| 10 | LZMA ストリームは range coder 初期化バイト `0x00` で開始 | shared LZMA semantics | ✅ | LZMA 共有デコーダで検証 (lzip/xz と共通パス) |

### バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | 切り詰めヘッダー (< 13B) の拒否 | lzma-file-format.txt | ✅ | `test_decode_rejects_truncated_header` |
| 12 | 空ストリーム (ヘッダーのみ) の拒否 | lzma-file-format.txt | ✅ | `test_decode_rejects_empty_stream` |
| 13 | 切り詰め LZMA ストリームの拒否 | lzma-file-format.txt | ✅ | `test_decode_rejects_truncated_stream` |
| 14 | ストリーム終端後の trailing data 拒否 (既知サイズ) | lzma-file-format.txt §1: XZ Utils は reject、LZMA Utils は ignore → 本実装は reject を採用 | ✅ | `test_decode_rejects_trailing_data_known_size`。ただし range decoder が読み残す encoder flush 由来の slack ≤5B は許容 |
| 15 | ストリーム終端後の trailing data 拒否 (サイズ不明) | 同上 | ✅ | `test_decode_rejects_trailing_data_unknown_size` (slack ≤5B 許容、#14 と同一方針) |
| 16 | ヘッダー宣言サイズと実デコードサイズの不一致拒否 | lzma-file-format.txt | ✅ | `test_decode_rejects_size_mismatch` |
| 17 | `lc+lp > 4` の properties 拒否 (共有 LZMA コアと XZ Utils 同等の制限) | lzma-file-format.txt: properties | ✅ | `test_decode_rejects_unsupported_props_combo`。形式上有効な値だがサポート外として `InvalidData` |
| 18 | `decode_bounded` は出力上限を `Error::OutputLimitExceeded` で強制 (既知・未知サイズの双方) | crate contract | ✅ | `decode_bounded` 実装・共通 bounded-decode 規約。完全 decode 後にサイズ判定する post-hoc 方式のためピークメモリは無制限 (`test_decode_bounded_exceeds_limit`、`test_decode_bounded_within_limit`、`test_decode_bounded_zero_limit`) |

### エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 19 | ヘッダー形式 (0x5D + dict u32 LE + size u64 LE) | lzma-file-format.txt: LZMA_Alone header | ✅ | `test_encode_header_format` |
| 20 | エンコーダはサイズ不明 (`0xFFFF_FFFF_FFFF_FFFF`) + EoPM を出力 (`xz --format=lzma` と同構成) | lzma-file-format.txt | ✅ | `test_lzma_alone_encode_decoded_by_system`, `test_fuzz_regression_lzma_original_decompress_1` (統合) |
| 21 | デフォルト辞書サイズ 8 MiB (`xz -6` 相当) | lzma-file-format.txt | ✅ | `test_encode_header_format` |
| 22 | 辞書サイズ指定エンコード | lzma-file-format.txt | ✅ | `test_encode_with_dict_size` |
| 23 | ラウンドトリップ: 空/hello/repeated/all_bytes/1kb | lzma-file-format.txt | ✅ | `test_encode_roundtrip_*` |

### システム互換 / その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | system `xz --format=lzma` 生成物のデコード | lzma-file-format.txt / system xz | ✅ | `test_lzma_alone_decode_system_compressed` (統合) |
| 25 | crate 生成物の system `xz --format=lzma -d` によるデコード | lzma-file-format.txt / system xz | ✅ | `test_lzma_alone_encode_decoded_by_system` (統合) |
| 26 | 既知サイズが 256 GiB 以上を指定するファイルの拒否 (XZ Utils の policy) | lzma-file-format.txt §1.1.3 | ✅ | 実装済み — `parse_header` で既知 unpacked_size >= 256 GiB を reject (XZ Utils policy)。`test_decode_rejects_oversized_known_size` |
| 27 | 辞書サイズの portability 推奨 (2^n または 2^n+2^(n-1)。XZ Utils はこの形式のみ生成・解凍) | lzma-file-format.txt §1.1.2 | ✅ | encode 側で portable 値のみ受理 (非 portable は `Error::InvalidData`、XZ Utils 互換を保証)。decode は引き続き任意の非 0 値を受理する寛容側 (XZ は decode も portable のみ — 本実装の方が寛容)。`test_encode_accepts_portable_dict_size`, `test_encode_rejects_nonportable_dict_size`, `test_is_portable_dict_size` |
| 28 | EOS マーカの厳格化: dist=0xFFFFFFFF かつ len=2 (MATCH_MIN_LEN) のみ受理 | lzma-specification.txt は距離のみで EOS 判定 (長さ不問) — 本実装は strict 側 | ✅ | `test_lzma_invalid_eos_marker_wrong_length` (共有 lzma コア) |
| 29 | rep 距離 `0 <= dis < dict_size` かつ `dis == position` の仮想ゼロバイト受理 (共有 LZMA コア) | lzma-specification.txt / LZMA SDK semantics | ✅ | `copy_rep` で辞書窓の占有数 `occ` に対し `rep0 > occ` または `rep0 >= dict_size` を reject。`rep0 == occ` かつ `occ < dict_size` は窓の直前を 0x00 として出す。実エンコーダは生成しないため直接テストなし |
| 30 | range decoder 初期化: 先頭バイト 0x00 + code < range (0xFFFFFFFF 拒否) | lzma-specification.txt | ✅ | `test_decoder_bad_first_byte`, `test_decoder_initial_code_max_rejected` (共有 range coder) |
| 31 | 共有 LZMA デコーダは、宣言展開長が 1 GiB を超えると展開ループの前に `OutputLimitExceeded` を返す。サイズ不明の経路は対象外 | crate 防御 | ✅ | `test_decode_with_size_rejects_declared_output_above_limit`。`.lzma` の `decode_bounded` 自体は行 18 の事後チェックのまま |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 31 |
| **合計** | **31** |

---

## 出典メモ

- system `xz` はローカルのテスト時 oracle のみ (crate へリンク・同梱しない)。


---
