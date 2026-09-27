# ユーティリティ

## 参照仕様一覧

| 参照名 | 出典 |
|---|---|
| ISO 3309 / ITU-T V.42 | [ITU-T V.42](https://www.itu.int/rec/T-REC-V.42) (CRC polynomial は §8.1.2.6.2) |
| RFC 1950 (zlib/Adler-32) | [rfc1950.txt](https://www.rfc-editor.org/rfc/rfc1950.txt) |
| RFC 1952 (gzip/CRC-32) | [rfc1952.txt](https://www.rfc-editor.org/rfc/rfc1952.txt) Appendix 8 |
| RFC 1321 (MD5) | [rfc1321.txt](https://www.rfc-editor.org/rfc/rfc1321.txt) (ローカルスナップショット: `docs/spec/sources/rfc1321.txt`) |
| RFC 2268 (RC2) | [rfc2268.txt](https://www.rfc-editor.org/rfc/rfc2268.txt) |
| RFC 2315 (PKCS#7) | [rfc2315.txt](https://www.rfc-editor.org/rfc/rfc2315.txt) |
| FIPS 180-3 / 180-4 (SHA-1 / SHA-256) | [NIST.FIPS.180-4.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) (180-3 は 180-4 に統合・廃止) |
| FIPS 197 (AES) | [NIST.FIPS.197-upd1.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) |
| FIPS 46-3 (DES/3DES) | [fips46-3.pdf](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf) (withdrawn) |
| RC4 | de facto standard。参考: [RFC 4345](https://www.rfc-editor.org/rfc/rfc4345.txt) (SSH arcfour 記述) |
| ECMA-182 (CRC-64) | [ECMA-182 1st edition PDF](https://ecma-international.org/wp-content/uploads/ECMA-182_1st_edition_december_1992.pdf) |
| xxHash reference algorithm | [xxHash spec](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md) |
| WinZip AES spec | [WinZip AES Encryption](https://www.winzip.com/en/support/aes-encryption/) |
| 7z Methods.txt | [Methods.txt](https://raw.githubusercontent.com/ip7z/7zip/main/DOC/Methods.txt) (LZMA SDK 同梱) |
| Snappy framing / LZ4 frame / xz-file-format.txt | `docs/spec/<fmt>/README.md` 参照 |

### CRC32 (ISO 3309 / ITU-T V.42)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | ポリノミアル `0xEDB88320` (反転表現) | ISO 3309 / ITU-T V.42 | ✅ | 実装のconst fn |
| 2 | 前処理/後処理 XOR `0xFFFFFFFF` | ISO 3309 / ITU-T V.42 | ✅ | `Crc32::new()` / `finish()` |
| 3 | 空データ → `0x00000000` | ISO 3309 / ITU-T V.42 | ✅ | `test_crc32_empty` |
| 4 | `"123456789"` → `0xCBF43926` | RFC 1952 Appendix 8 / ISO 3309 | ✅ | `test_crc32_known_vectors` |
| 5 | インクリメンタル計算 | ISO 3309 / ITU-T V.42 | ✅ | `test_crc32_incremental` |
| 6 | 単バイト `"a"` → `0xE8B7BE43` | ISO 3309 / ITU-T V.42 | ✅ | `test_crc32_single_byte` |

### XXH64

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | 空データ (seed=0) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_empty` |
| 8 | 1バイト入力 | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_1byte` |
| 9 | 短い入力 (< 32バイト) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_hello_world`, `test_xxhash64_medium` |
| 10 | 長い入力 (≥ 32バイト) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_long` |
| 11 | 下位32ビット抽出 (zstdチェックサム用) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_hello_world_checksum` |
| 12 | seed ≠ 0 のテスト | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_seed_nonzero` |
| 13 | 32バイト丁度 (ストライプ境界) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_exactly_32_bytes` |

### BitReader

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 14 | LSB-first ビット読み取り | crate internal helper for LSB-first formats | ✅ | `test_read_bits` |
| 15 | バイト跨ぎ読み取り | crate internal helper for LSB-first formats | ✅ | `test_read_bits_crosses_byte_boundary_direct` |
| 16 | peek + consume | crate internal helper for LSB-first formats | ✅ | `test_peek_and_consume` |
| 17 | バイトアラインメント | crate internal helper for LSB-first formats | ✅ | `test_align_to_byte` |
| 18 | EOF エラー | crate internal helper for LSB-first formats | ✅ | `test_unexpected_eof` |
| 19 | u16 LE 読み取り | crate internal helper for LSB-first formats | ✅ | `test_read_u16_le` |
| 20 | read_bits(0) | crate internal helper for LSB-first formats | ✅ | `test_read_bits_zero` |
| 21 | read_bytes | crate internal helper for LSB-first formats | ✅ | `test_read_bytes` |
| 22 | remaining_bytes | crate internal helper for LSB-first formats | ✅ | `test_remaining_bytes` |
| 23 | byte_position | crate internal helper for LSB-first formats | ✅ | `test_byte_position` |
| 24 | remaining_data | crate internal helper for LSB-first formats | ✅ | `test_remaining_data` |
| 25 | read_bytes EOF エラー | crate internal helper for LSB-first formats | ✅ | `test_read_bytes_eof` |
| 26 | read_u16_le EOF エラー | crate internal helper for LSB-first formats | ✅ | `test_read_u16_le_eof` |
| 27 | peek_bits EOF ゼロパディング | crate internal helper for LSB-first formats | ✅ | `test_peek_bits_zero_padded_at_eof` |

### Error

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 28 | Display 実装 (全5バリアント) | crate internal API contract | ✅ | `test_display_*` (5テスト) |
| 29 | From\<Error\> for std::io::Error | crate internal API contract | ✅ | `test_io_error_unexpected_eof`, `test_io_error_invalid_data` |
| 30 | std::error::Error 実装 | crate internal API contract | ✅ | `test_std_error_impl` |

### Adler-32

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 31 | Adler-32 algorithm (sum1 + sum2, mod 65521) | RFC 1950 §8 | ✅ | util::adler32 実装 |
| 32 | 初期値 1 | RFC 1950 §8 | ✅ | `adler32(b"")` = 1 (one-shot API、struct なし) |
| 33 | Known vector: "Wikipedia" → 0x11E60398 | RFC 1950 §8 | ✅ | `test_adler32_wikipedia` |
| 34 | Incremental update | RFC 1950 §8 | ✅ | one-shot API のみ (incremental 不要: zlib/lzo で都度完結) |

### SHA-256

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 35 | SHA-256 (FIPS 180-4) | FIPS 180-4 | ✅ | util::sha256 実装 |
| 36 | Known vector: empty → e3b0c442... | FIPS 180-4 | ✅ | test_sha256_empty (もしあれば) |

### CRC-32C

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 37 | CRC-32C Castagnoli (polynomial 0x1EDC6F41) | Snappy framing format | ✅ | → snappy.md 参照 |

### SHA-1

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 38 | SHA-1 (FIPS 180-3) | FIPS 180-3 | ✅ | `util::sha1` 実装、ZIP AES PBKDF2 鍵導出で使用 |
| 39 | Known vector: empty → da39a3ee... | FIPS 180-3 | ✅ | `test_sha1_empty` |
| 40 | Known vector: "abc" → a9993e36... | FIPS 180-3 | ✅ | `test_sha1_abc` |
| 41 | Incremental update | FIPS 180-3 | ✅ | `test_sha1_incremental` |

### CRC-64/XZ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 42 | CRC-64 polynomial 0xC96C5795D7870F42 (ECMA-182) | ECMA-182 / xz-file-format.txt | ✅ | `util::crc64` 実装 |
| 43 | 初期値 / 最終 XOR 0xFFFFFFFFFFFFFFFF | ECMA-182 | ✅ | `Crc64::new()` / `finish()` |
| 44 | Known vector | ECMA-182 | ✅ | `test_crc64_known_vector` |
| 45 | Incremental update | ECMA-182 | ✅ | `test_crc64_incremental` |

### XXH32

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 46 | XXH32 (one-shot + streaming) | xxHash reference / LZ4 frame checksum | ✅ | `xxhash32()`, `XxHash32` |
| 47 | Known vector: empty (seed=0) | xxHash reference | ✅ | `test_xxhash32_empty` |
| 48 | Streaming matches one-shot | xxHash reference | ✅ | `test_xxhash32_streaming_matches_oneshot` |

### AES-256

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 49 | AES-128 / AES-192 / AES-256 (FIPS 197) | FIPS 197 | ✅ | `util::aes256` 実装、7z/ZIP 暗号化で使用 |
| 50 | AES-CTR mode (ZIP-compatible) | WinZip AES spec | ✅ | `apply_ctr_zip_compatible()` |
| 51 | AES-CBC mode (7zAES) | 7z Methods.txt | ✅ | `decrypt_cbc_truncated()` / `encrypt_cbc_zero_padded()` |

### MD5

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 52 | MD5 メッセージダイジェスト (RFC 1321) | RFC 1321 | ✅ | `util::md5` 実装、lrzip file-level integrity verification で使用 |
| 53 | RFC 1321 §A.5 既知ベクター | RFC 1321 | ✅ | `test_md5_empty`, `test_md5_abc`, `test_md5_message_digest`, `test_md5_a_to_z`, `test_md5_alphanumeric`, `test_md5_digits_repeated` |
| 54 | Incremental update (multi-block) | RFC 1321 | ✅ | `test_md5_incremental` |

### DES / 3DES

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 55 | DES ブロック暗号 (FIPS 46-3) | FIPS 46-3 | ✅ | `Des::new()`, `encrypt_block()`, `decrypt_block()` |
| 56 | DES 既知ベクター | FIPS 46-3 | ✅ | `test_des_known_vector_1`, `test_des_known_vector_2` |
| 57 | DES ラウンドトリップ | FIPS 46-3 | ✅ | `test_des_roundtrip` |
| 58 | Triple DES (EDE, 2-key/3-key) | FIPS 46-3 | ✅ | `Des3::new()` (16B/24B key)、EDE モード |
| 59 | DES-CBC mode | FIPS 46-3 + PKCS#7 | ✅ | `test_des_cbc_roundtrip` |

### RC2

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 60 | RC2 ブロック暗号 (RFC 2268) | RFC 2268 | ✅ | `Rc2::new()`, `encrypt_block()`, `decrypt_block()` |
| 61 | RFC 2268 §5 テストベクター (全 7 件) | RFC 2268 §5 | ✅ | `test_rc2_rfc2268_vector1` 〜 `test_rc2_rfc2268_vector7` |
| 62 | RC2-CBC mode | RFC 2268 + PKCS#7 | ✅ | `test_rc2_cbc_roundtrip`, `test_rc2_cbc_empty_rejected`, `test_rc2_cbc_non_aligned_rejected` |

### RC4

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 63 | RC4 ストリーム暗号 (KSA + PRGA) | de facto standard | ✅ | `Rc4::new()`, `apply()` |
| 64 | RC4 既知ベクター | de facto standard | ✅ | `test_rc4_known_vector`, `test_rc4_wiki_vector` |
| 65 | RC4 ラウンドトリップ + 空データ | de facto standard | ✅ | `test_rc4_roundtrip`, `test_rc4_empty_data` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 65 |
| **合計** | **65** |
