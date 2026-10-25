# lrzip (長距離圧縮フォーマット)

| 項目 | 内容 |
|------|------|
| 基準仕様 | upstream [`ckolivas/lrzip`](https://github.com/ckolivas/lrzip) の [`doc/magic.header.txt`](https://github.com/ckolivas/lrzip/blob/master/doc/magic.header.txt) + ソースコード (0.6x 系、ローカルスナップショット: `docs/spec/sources/lrzip_magic.header.txt`)。本 crate は crate-local subset のため完全互換は保証しない |
| 参照実装 | upstream `lrzip` (Con Kolivas 他、GPL-2.0-or-later、動作参照 — format facts のみ、コード取り込みなし。GPL-2.0+→GPL-3→AGPL-13 の変換パスあり)。system `lrzip` は oracle (下記「相互運用の確認範囲」行参照) および性能比較 (`docs/bench/`)。詳細: THIRD_PARTY_NOTICES lrzip / rzip 項 |
| 形式概要 | crate-local な `.lrz` framing を持ち、shared long-range match finder の上に lrzip-specific variable-width match offset token を載せる。system `lrzip` との完全互換 reimplementation は目標外 |
| 内部構成 | crate-local shared `rzip`-style token/chunk logic を再利用し、その上に `LZMA` / `bzip2` / `LZO` / `gzip` / `ZPAQ` / `none` バックエンドを重ねる |
| `magic.header.txt` でカバーしない残余の de facto 事実 | ctype 数値写像 (none/bzip2/lzo/lzma/gzip/zpaq)、stream header は CTYPE_NONE プレースホルダで実 ctype は block header 側にだけ置く layout、empty stream0 = CRC + 0-length literal token、stream-0 の token エンコーディング、可変幅 match offset、chunk sizing (~100MiB)、生データフォールバック方針、system `lrzip` の LZMA block は EOS marker を持たず block header `u_len` で終端する raw stream、stdin/pipe 出力は header `dict_size == 0` — いずれも upstream ソース由来の format fact であり、書面仕様が存在しないため例外として記録する |
| system `lrzip` 相互運用の確認範囲 | 現在の実測確認は system `lrzip` 生成の simple / match-rich LZMA archive decode と、crate 出力を system `lrzip -d` が decode できる LZMA / `bzip2` / `LZO` / `gzip` / `ZPAQ` / `none` backend matrix と MD5 flag 付き出力まで。未検証の option matrix や large-payload outer framing 全体との完全互換は保証の対象外とする |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| `.lrz` outer framing (crate-local) | crate-local `.lrz` header layout | ✅ | ✅ | system `lrzip` との完全互換 reimplementation は目標外 |
| backend: LZMA / bzip2 / LZO / gzip / ZPAQ / none | lrzip backend policy | ✅ | ✅ | `lrzip -d` での decode 相互運用確認済み |

### ヘッダー

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | マジックナンバー ("LRZI") | crate-local `.lrz` header layout | ✅ | `test_header_format`, `test_lrzip_roundtrip_hello` |
| 2 | バージョンフィールド (major=0, minor=6) | crate-local `.lrz` header layout | ✅ | `test_header_format`, `test_header_version_minor_updated` |
| 3 | unsupported major version reject | crate-local `.lrz` header layout | ✅ | `test_unsupported_version` |
| 4 | ファイルサイズフィールド (u64 LE) | crate-local `.lrz` header layout | ✅ | デコーダーで検証 |
| 5 | LZMA props byte を妥当値としてパース | crate-local `.lrz` header layout | ✅ | `test_non_default_lzma_props_byte_supported`, `test_invalid_lzma_props_byte` |
| 6 | encryption flag 非ゼロ拒否 | crate-local `.lrz` header layout | ✅ | `test_encrypted_rejected` |
| 7 | 不正マジックエラー | crate-local `.lrz` header layout | ✅ | デコーダーで `InvalidData` 返却 |
| 8 | ヘッダー短すぎエラー | crate-local `.lrz` header layout | ✅ | デコーダーで `UnexpectedEof` 返却、`test_decode_truncated_at_every_position` (全切断位置で拒否) |

### rzip アルゴリズム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 9 | ローリングハッシュ (31バイトウィンドウ) | upstream `rzip.samba.org` token/chunk semantics | ✅ | `test_lrzip_roundtrip_large` (50KB で長距離マッチ発生) |
| 10 | リテラルトークン (tag=0x00 + u16 長 + データ) | upstream `rzip.samba.org` token/chunk semantics | ✅ | 全ラウンドトリップテスト |
| 11 | マッチトークン (non-zero tag + offset:u32 + u16 長) | upstream `rzip.samba.org` token/chunk semantics | ✅ | `test_nonzero_rzip_token_offset_validated`, `test_rzip_match_offset_zero_rejected` |
| 12 | リテラル/マッチ混合ストリーム | upstream `rzip.samba.org` token/chunk semantics | ✅ | `test_lrzip_roundtrip_large` |
| 13 | non-zero match token の offset 妥当性検証 | upstream `rzip.samba.org` token/chunk semantics | ✅ | `test_nonzero_rzip_token_offset_validated` |
| 14 | rzip マッチオフセット = 0 / 範囲外拒否 | upstream `rzip.samba.org` token/chunk semantics | ✅ | `test_rzip_match_offset_zero_rejected` |
| 15 | ブロックチェーンサイクル検出 (10000 ブロック制限) | upstream `rzip.samba.org` token/chunk semantics | ✅ | `test_block_chain_cycle_detected` |

### バックエンド

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | lzip フォーマット経由の LZMA 圧縮 | lrzip backend policy / lzip payload semantics | ✅ | 全ラウンドトリップテスト |
| 17 | bzip2 backend roundtrip | lrzip backend policy / bzip2 payload semantics | ✅ | `test_roundtrip_bzip2`, `test_roundtrip_bzip2_backend` |
| 18 | LZO backend roundtrip | lrzip backend policy / LZO payload semantics | ✅ | `test_roundtrip_lzo`, `test_roundtrip_lzo_backend` |
| 19 | gzip backend roundtrip | lrzip backend policy / gzip payload semantics | ✅ | `test_roundtrip_gzip`, `test_roundtrip_gzip_backend` |
| 20 | ZPAQ backend roundtrip | lrzip backend policy / ZPAQ payload semantics | ✅ | `test_roundtrip_zpaq`, `test_roundtrip_zpaq_backend` |
| 21 | none backend roundtrip | lrzip backend policy / uncompressed payload semantics | ✅ | `test_roundtrip_none`, `test_roundtrip_none_backend` |
| 22 | 圧縮効果なし時の生データフォールバック | lrzip backend policy / payload selection policy | ✅ | `test_compress_stream_falls_back_for_tiny_backend_matrix`, `test_compress_stream_keeps_lzma_backend_for_literal_heavy_input` |
| 23 | 100MiB chunk multiple 単位の分割 | lrzip backend policy / chunk sizing | ✅ | `test_roundtrip_chunk_multiple_boundary`, `test_chunk_multiple_boundary_splits_into_two_chunks` |

### エンコード/デコード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | ラウンドトリップ (短データ) | crate-local `.lrz` container contract | ✅ | `test_lrzip_roundtrip_hello` |
| 25 | ラウンドトリップ (大データ) | crate-local `.lrz` container contract | ✅ | `test_lrzip_roundtrip_large` (50KB), `test_roundtrip_chunk_multiple_boundary` (100MB+64) |
| 26 | 出力サイズ不一致検出 | crate-local `.lrz` container contract | ✅ | `test_size_mismatch`, `test_lrzip_decode_detects_output_size_mismatch` |
| 27 | system `lrzip` 生成 LZMA archive の decode | system `lrzip` interoperability behavior | ✅ | `test_lrzip_decode_system_lzma_archive` |
| 28 | crate 出力を system `lrzip` が decode 可能 (LZMA path) | system `lrzip` interoperability behavior | ✅ | `test_lrzip_encode_system_decode_compat` |
| 29 | crate 出力を system `lrzip` が decode 可能 (non-LZMA backend matrix) | system `lrzip` interoperability behavior | ✅ | `test_lrzip_encode_bzip2_system_decode_compat`, `test_lrzip_encode_gzip_system_decode_compat`, `test_lrzip_encode_none_system_decode_compat`, `test_lrzip_encode_lzo_system_decode_compat`, `test_lrzip_encode_zpaq_system_decode_compat` |
| 30 | system `lrzip` 生成 match-rich LZMA archive の decode | system `lrzip` interoperability behavior | ✅ | `test_lrzip_decode_system_lzma_repeated_archive` |
| 30a | system `lrzip` の LZMA block は EOS-less raw stream で、block header `u_len` を終端サイズとして decode。header `dict_size == 0` (stdin/pipe 出力) は辞書制約なし (`u32::MAX`) として扱う | system `lrzip` de facto | ✅ | `test_decompress_block_lzma_without_eos_marker`, `test_decode_system_lrzip_zeros_archive`, `test_decode_system_lrzip_zeros_archive_zero_dict` |
| 31 | encode_writer (std::io::Write 対応) | crate-local `.lrz` container contract | ✅ | doctest |
| 32 | decode_reader / decode_to_writer (std::io 対応) | crate-local `.lrz` container contract | ✅ | doctest, `test_decode_to_writer_roundtrip`。reader path は slice `decode()` より検証が弱い既知差分: `next_head != 0` (1 chunk 内 multi-block) は `Unsupported`、MD5 flag は読まず digest 未検証、stream header の `last_head` を無視して block を順読み |
| 33 | Backend type byte encoding (数値) | lrzip header | ✅ | 実装済み |
| 34 | Unknown backend type reject | lrzip header | ✅ | `test_decompress_block_rejects_unknown_ctype` |
| 35 | Variable-width match offset token format | lrzip token layer | ✅ | `test_reencode_stream0_for_lrzip_reduces_match_offset_width` |
| 36 | MD5 checksum flag (header byte 21): パース + 検証 + emit | lrzip header | ✅ | decode: `md5_flag != 0` 時にデコード結果の MD5 を検証 (`test_decode_md5_flag_valid`, `test_decode_md5_flag_mismatch`, `test_decode_md5_flag_truncated`)。encode: `encode_with_md5` で flag + 末尾 digest を出力 (`test_encode_with_md5_roundtrip`, `test_encode_with_md5_empty`, `test_encode_with_md5_backend_matrix`) |
| 37 | Reserved byte 23: encode 時は 0 | lrzip header | ✅ | エンコーダーで 0 書き出し |
| 38 | MD5 flag 付き crate 出力を system `lrzip -d` が decode (digest 検証通過) | system `lrzip` interoperability behavior | ✅ | `test_lrzip_encode_md5_system_decode_compat` |
| 39 | v0.6 RCD 構造 (RCD0 幅 1-8、EOF flag、chunk decompressed size、stream header ctype/c_len/u_len/last_head) | magic.header.txt v0.6 RCD | ✅ | `decode.rs` RCD パース実装、`test_invalid_chunk_bytes_zero`、`test_invalid_chunk_bytes_too_large` |
| 40 | v0.6 data blocks: stream0 末端の empty literal (type 0, len 0) + CRC32 | magic.header.txt v0.6 Data blocks | ✅ | `decode_chunk_streams` で `legacy_crc32` 検証、`test_crc32_verified` |
| 41 | magic bytes 6-13 の Source File Size は unknown 時 0 (upstream 記載) | magic.header.txt | ✅ | 実装済み — `total_size == 0` は unknown として size 検査を skip (decode / streaming reader 双方)。`test_zero_total_size_is_unknown` |
| 42 | v0.7 節 (byte 14 streaming flag、byte 23 last-block、LRZC、CryptoDesc、minor=0x07) および v0.5x 以前の旧レイアウト (固定長 stream header、RCD0 なし) | magic.header.txt v0.7 / v0.5x | ❌ | intentional scope。対象を 0.6x に限定しているため、`minor != 6` は `Error::Unsupported` で拒否する (slice / reader 両 path。旧レイアウトを v0.6 として誤パースしないよう `minor < 6` も拒否) (`test_decode_rejects_minor_above_6`, `test_decode_rejects_minor_below_6`) |
| 43 | ZPAQ ブロックの実効上限は `min(宣言 u_len, ceiling)`。`decode` / reader の ceiling は `usize::MAX`（追加天井なし）。`decode_bounded(max_output)` は `max_output` を ceiling にする。非空 payload で `u_len == 0` または `u_len == usize::MAX` は `InvalidData`（`zpaq::decode_bounded` はどちらも無制限）。`max_output == 0` の非空 ZPAQ ブロックは復号せず `OutputLimitExceeded` | crate contract / fuzz run-1792163723 | ✅ | `zpaq_block_rejects_unusable_declared_size`, `zpaq_ff_fill_is_bounded_by_declared_u_len`。PASS の正当ブロックは `decoded == u_len` で成功する (`test_roundtrip_zpaq`, `test_roundtrip_zpaq_backend`) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 43 |
| ⚠️ 部分実装  | 0 |
| ❌ 未実装 | 1 (intentional scope) |
| **合計** | **44** |
