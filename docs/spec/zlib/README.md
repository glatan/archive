# zlib (RFC 1950)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950.txt) — ZLIB Compressed Data Format Specification version 3.3 (ローカルスナップショット: `docs/spec/sources/rfc1950.txt`) |
| current scope | RFC 1950 の zlib wrapper として、2-byte header (`CMF`/`FLG`)・raw DEFLATE payload・big-endian Adler-32 trailer を対象にする |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | `CMF` の `CM=8` (deflate) 検証 | RFC 1950 §2.2 | ✅ | `test_bad_cm`, `test_header_valid` |
| 2 | `CMF`/`FLG` の `FCHECK` 検証 | RFC 1950 §2.2 | ✅ | `test_bad_fcheck`, `test_header_valid` |
| 3 | `FDICT=1`: decode は `decode_with_dict()` で対応、`decode()` は reject | RFC 1950 §2.2 | ✅ | `decode()` で `Unsupported` 返却、`decode_with_dict()` でプリセット辞書デコード対応 |
| 4 | 入力短すぎエラー | RFC 1950 §2.2 / §2.3 | ✅ | `test_too_short` |
| 5 | raw DEFLATE payload decode | RFC 1950 §2.2 / RFC 1951 | ✅ | `decode()` で実施、`test_roundtrip`, `test_roundtrip_large` |
| 6 | Adler-32 trailer 検証 | RFC 1950 §2.2 | ✅ | `test_adler32_mismatch` |
| 7 | encode: `CMF=0x78` / 32KiB window | RFC 1950 §2.2 | ✅ | `test_header_valid` |
| 8 | encode: `FLG` の `FCHECK` 自動調整 | RFC 1950 §2.2 | ✅ | `test_header_valid` |
| 9 | encode → decode roundtrip | RFC 1950 §2.2 / §2.3 | ✅ | `test_roundtrip`, `encode::tests::test_roundtrip` |
| 10 | 空入力 roundtrip | RFC 1950 §2.2 / §2.3 | ✅ | `test_roundtrip_empty` |
| 11 | 大入力 roundtrip | RFC 1950 §2.2 / §2.3 | ✅ | `test_roundtrip_large` |
| 12 | `FDICT=1`: preset dictionary 対応 | RFC 1950 §2.2 | ✅ | `decode_with_dict()`, `encode_with_dict()`, `test_decode_with_dict_roundtrip`, `test_decode_with_dict_wrong_dict_rejected` |
| 13 | `FLEVEL` (bits 6-7): 圧縮レベル情報 | RFC 1950 §2.2 | ✅ | `decode_with_info()` で `ZlibInfo.flevel` に公開。`test_decode_with_info_flevel`, `test_decode_with_info_flevel_variants` |
| 14 | `CINFO` (bits 4-7): window size 0-7 | RFC 1950 §2.2 | ✅ | `cinfo > 7` を reject (`test_cinfo_above_7_rejected`) |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | CINFO > 7 rejection (CM=8 時に CINFO は 0-7 のみ有効) | RFC 1950 §2.2 | ✅ | `test_cinfo_above_7_rejected` |
| 16 | Adler-32 algorithm: (sum1, sum2) mod 65521 | RFC 1950 §8 | ✅ | util::adler32 |
| 17 | Adler-32 modulus 65521 | RFC 1950 §8 | ✅ | 実装済み |
| 18 | 全 multi-byte 数値は MSB first (big-endian) で格納 | RFC 1950 §2.1 | ✅ | Adler-32 trailer を big-endian で読み書き |
| 19 | FDICT=0 を期待するコンテキストで FDICT=1 を reject | RFC 1950 §2.3 | ✅ | decode() は FDICT=1 で Unsupported、decode_with_dict() で対応 |
| 20 | ADLER32 以後のデータは zlib ストリームに含まれない (trailing data 許容) | RFC 1950 §2.2 | ❌ | 実装は trailer を末尾 4B 固定と仮定するため trailing data は reject (intentional な厳格化) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 19 |
| ❌ 未実装 | 1 (intentional scope) |
| **合計** | **20** |

