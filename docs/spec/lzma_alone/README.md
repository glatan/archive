# LZMA-Alone (`.lzma`)

| 項目 | 内容 |
|------|------|
| 形式概要 | 13バイトヘッダー (properties byte + 辞書サイズ + 非圧縮サイズ) + 生 LZMA ストリーム |
| 基準仕様 | [`lzma-file-format.txt`](https://raw.githubusercontent.com/tukaani-project/xz/master/doc/lzma-file-format.txt) (tukaani-project/xz `doc/`、2022-07-13 版、public domain。ローカルスナップショット: `docs/spec/sources/lzma-file-format-20220713.txt`) |

### ヘッダーフォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | ヘッダーサイズ 13 バイト | lzma-file-format.txt: "The .lzma File Format" | ✅ | `test_encode_header_format` |
| 2 | properties byte (offset 0): `(pb*5+lp)*9+lc`、0..=224 | lzma-file-format.txt: LZMA_Alone header / properties | ✅ | `test_decode_rejects_invalid_props_byte` |
| 3 | 辞書サイズ (offset 1-4, uint32 LE) | lzma-file-format.txt: LZMA_Alone header | ✅ | `test_encode_header_format` |
| 4 | 辞書サイズ 0 の拒否 | lzma-file-format.txt: LZMA_Alone header (0 は無効) | ✅ | `test_decode_rejects_zero_dict_size`, `test_encode_rejects_zero_dict_size` |
| 5 | 非圧縮サイズ (offset 5-12, uint64 LE) | lzma-file-format.txt: LZMA_Alone header | ✅ | `test_encode_header_format` |
| 6 | 非圧縮サイズ `0xFFFF_FFFF_FFFF_FFFF` = サイズ不明 | lzma-file-format.txt: LZMA_Alone header | ✅ | `test_decode_unknown_size`, `test_lzma_alone_decode_system_compressed` (統合) |

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
| 14 | ストリーム終端後の trailing data 拒否 (既知サイズ) | lzma-file-format.txt: XZ Utils は reject、LZMA Utils は ignore → 本実装は reject を採用 | ✅ | `test_decode_rejects_trailing_data_known_size` |
| 15 | ストリーム終端後の trailing data 拒否 (サイズ不明) | 同上 | ✅ | `test_decode_rejects_trailing_data_unknown_size` |
| 16 | ヘッダー宣言サイズと実デコードサイズの不一致拒否 | lzma-file-format.txt | ✅ | `test_decode_rejects_size_mismatch` |
| 17 | `lc+lp > 4` の properties 拒否 (共有 LZMA コアと XZ Utils 同等の制限) | lzma-file-format.txt: properties | ✅ | `test_decode_rejects_unsupported_props_combo`。形式上有効な値だがサポート外として `InvalidData` |
| 18 | `decode_bounded` は出力上限を `Error::OutputLimitExceeded` で強制 (既知・未知サイズの双方) | crate contract | ✅ | `decode_bounded` 実装・共通 bounded-decode 規約 |

### エンコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 19 | ヘッダー形式 (0x5D + dict u32 LE + size u64 LE) | lzma-file-format.txt: LZMA_Alone header | ✅ | `test_encode_header_format` |
| 20 | エンコーダは既知サイズ + EoPM を出力 (`xz --format=lzma` と同構成) | lzma-file-format.txt | ✅ | `test_lzma_alone_encode_decoded_by_system` (統合) |
| 21 | デフォルト辞書サイズ 8 MiB (`xz -6` 相当) | lzma-file-format.txt | ✅ | `test_encode_header_format` |
| 22 | 辞書サイズ指定エンコード | lzma-file-format.txt | ✅ | `test_encode_with_dict_size` |
| 23 | ラウンドトリップ: 空/hello/repeated/all_bytes/1kb | lzma-file-format.txt | ✅ | `test_encode_roundtrip_*` |

### システム互換 / その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | system `xz --format=lzma` 生成物のデコード | lzma-file-format.txt / system xz | ✅ | `test_lzma_alone_decode_system_compressed` (統合) |
| 25 | crate 生成物の system `xz --format=lzma -d` によるデコード | lzma-file-format.txt / system xz | ✅ | `test_lzma_alone_encode_decoded_by_system` (統合) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 25 |
| **合計** | **25** |

---

## 出典メモ

- system `xz` はローカルのテスト時 oracle のみ (crate へリンク・同梱しない)。


---
