# ZIP — compression methods

## §4.4.5 Compression Method

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 67 | Method 0: Stored (no compression) | §4.4.5 | ✅ | `test_decode_store_single_file` |
| 68 | Method 1: Shrunk | §4.4.5, §5.1 | ✅ | decode + encode: `unshrink::{unshrink, shrink}`、`ZipCompression::Shrunk` |
| 69 | Method 2-5: Reduced (factor 1-4) | §4.4.5, §5.2 | ✅ | decode + encode: `expand::{expand, reduce}`、`ZipCompression::Reduce(factor)` |
| 70 | Method 6: Imploded | §4.4.5, §5.3 | ✅ | decode + encode: `implode::{implode, implode_encode}`、`ZipCompression::Implode` |
| 71 | Method 8: Deflated | §4.4.5, §5.5 | ✅ | `test_decode_deflate_single_file` |
| 72 | Method 9: Enhanced Deflating (Deflate64) | §4.4.5, §5.6 (+ Info-ZIP deflate64 de facto 挙動。距離コード 30/31・長さコード 285 の拡張ビット詳細は APPNOTE 未記載) | ✅ | decode + encode: `deflate64::{decode, encode}`、`ZipCompression::Deflate64` |
| 73 | Method 10: PKWARE DCL Implode | §4.4.5, §5.13 (空見出し) + blast.c de facto | ✅ | decode + literal-only encode 対応 (`dcl_implode::dcl_implode_decode`/`dcl_implode_encode`、固定木・lit=0 raw literal + EOS emit。外部 encoder 未参照)。`test_dcl_implode_literal_only`, `test_dcl_implode_back_reference`, `test_dcl_implode_roundtrip_with_known_vector`, `test_dcl_implode_encode_roundtrip`, `test_dcl_implode_encode_random_roundtrip`, `test_zip_method10_encode_roundtrip` |
| 74 | Method 12: BZIP2 | §4.4.5, §5.7 | ✅ | decode + encode: `ZipCompression::Bzip2` (`bzip2` feature) |
| 75 | Method 14: LZMA | §4.4.5, §5.8 | ✅ | decode + encode: `ZipCompression::Lzma` |
| 76 | Method 93: Zstandard | §4.4.5 | ✅ | decode + encode: `ZipCompression::Zstd` (`zstd` feature) |
| 77 | Method 95: XZ | §4.4.5 | ✅ | decode + encode: `ZipCompression::Xz` (`xz` feature) |
| 78 | Method 98: PPMd version I Rev 1 | §4.4.5, §5.10 | ✅ | decode + encode: `ZipCompression::Ppmd` |
| 79 | Method 99: AE-x encryption marker | §4.4.5, Appendix E | ✅ | AES encryption で使用 |
| 80 | 未知メソッド reject | §4.4.5 | ✅ | `Unsupported("zip: compression method")`。APPNOTE 登録だが非対応の method ID: 18 (IBM TERSE new)、19 (IBM LZ77 z Architecture)、94 (MP3) — 他の未実装 ID と同様に汎用 reject 経路 |

---

## §5 Compression Method Details (未対応分)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 127 | §5.1 UnShrinking (Method 1) | §5.1 | ✅ | decode + encode。queue 規則準拠 (hwzip) の decoder 修正 + `shrink` encoder |
| 128 | §5.2 Expanding (Methods 2-5) | §5.2 | ✅ | decode + encode: follower sets + DLE/LZ77 (hwzip 準拠 wire format に修正) + `reduce` encoder |
| 129 | §5.3 Imploding (Method 6) | §5.3 | ✅ | decode + encode: RLE コードテーブル + 反転 canonical コード (hwzip 準拠 wire format に修正) + `implode_encode` |
| 130 | §5.5 Deflating (Method 8) details | §5.5 | ✅ | 既存 DEFLATE module で対応 |
| 131 | §5.6 Enhanced Deflating (Method 9 / Deflate64) | §5.6 (+ Info-ZIP deflate64 de facto 挙動) | ✅ | decode + encode: `deflate64` モジュール、`ZipCompression::Deflate64` |
| 132 | §5.7 BZIP2 (Method 12) | §5.7 | ✅ | decode + encode (`bzip2` feature) |
| 133 | §5.8 LZMA (Method 14): LZMA Properties Header (4B) + stream | §5.8 | ✅ | decode + encode |
| 134 | §5.10 PPMd (Method 98): 2B parameter + stream | §5.10 | ✅ | decode + encode |
| 135 | §5.17 IBM z/OS CMPSC (Method 16) | §5.17 | ✅ | `cmpsc` feature 有効時は `compress::cmpsc` で basic method を decode/encode (encode は alphabet-only 非圧縮 emit、`test_zip_method16_encode_roundtrip`) (`test_decode_cmpsc_method16_roundtrip` / `test_decode_cmpsc_method16_corrupt_rejected`)。feature 無効時は `Unsupported`。entropy-encoding 拡張と flag 0x40 deflate 圧縮辞書は codec 側で拒否 (intentional scope) |

---
