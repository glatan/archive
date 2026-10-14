# ユーティリティ

## 参照仕様一覧

| 参照名 | 出典 |
|---|---|
| ISO 3309 / ITU-T V.42 | [ITU-T V.42](https://www.itu.int/rec/T-REC-V.42) (CRC polynomial は §8.1.2.6.2) |
| RFC 1950 (zlib/Adler-32) | [rfc1950.txt](https://www.rfc-editor.org/rfc/rfc1950.txt) |
| RFC 1952 (gzip/CRC-32) | [rfc1952.txt](https://www.rfc-editor.org/rfc/rfc1952.txt) Appendix 8 |
| RFC 1321 (MD5) | [rfc1321.txt](https://www.rfc-editor.org/rfc/rfc1321.txt) (ローカルスナップショット: `docs/spec/sources/rfc1321.txt`) |
| FIPS 180-4 (SHA-1 / SHA-256) | [NIST.FIPS.180-4.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) (前身の 180-3 は統合・廃止) |
| FIPS 197 (AES) | [NIST.FIPS.197-upd1.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) |
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
| 9 | 短い入力 (< 32バイト) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_hello_world`、`test_xxhash64_medium`、`test_xxhash64_tail_boundaries` (8/4/1 バイト内部境界) |
| 10 | 長い入力 (≥ 32バイト) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_long` |
| 11 | 下位32ビット抽出 (zstdチェックサム用) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_hello_world_checksum` |
| 12 | seed ≠ 0 のテスト | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_seed_nonzero` |
| 13 | 32バイト丁度 (ストライプ境界) | xxHash reference algorithm / RFC 8878 checksum usage | ✅ | `test_xxhash64_exactly_32_bytes`、`test_xxhash64_stripe_boundary_streaming` (31/32/33、63/64/65) |

### BitReader

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 14 | LSB-first ビット読み取り | crate internal helper for LSB-first formats | ✅ | `test_read_bits` |
| 15 | バイト跨ぎ読み取り | crate internal helper for LSB-first formats | ✅ | `test_read_bits_crosses_byte_boundary_direct` |
| 16 | peek + consume | crate internal helper for LSB-first formats | ✅ | `test_peek_and_consume`、`test_peek_bits_at_empty_stream`、`test_consume_more_than_buffered` |
| 17 | バイトアラインメント | crate internal helper for LSB-first formats | ✅ | `test_align_to_byte` |
| 18 | EOF エラー | crate internal helper for LSB-first formats | ✅ | `test_unexpected_eof`、`test_read_bits_past_end` |
| 19 | u16 LE 読み取り | crate internal helper for LSB-first formats | ✅ | `test_read_u16_le` |
| 20 | read_bits(0) | crate internal helper for LSB-first formats | ✅ | `test_read_bits_zero` |
| 21 | read_bytes | crate internal helper for LSB-first formats | ✅ | `test_read_bytes`、`test_read_bytes_served_from_bit_buffer`、`test_read_bytes_put_back_past_buffered` |
| 22 | remaining_bytes | crate internal helper for LSB-first formats | ✅ | `test_remaining_bytes` |
| 23 | byte_position | crate internal helper for LSB-first formats | ✅ | `test_byte_position` |
| 24 | remaining_data | crate internal helper for LSB-first formats | ✅ | `test_remaining_data`、`test_remaining_data_unaligned` |
| 25 | read_bytes EOF エラー | crate internal helper for LSB-first formats | ✅ | `test_read_bytes_eof` |
| 26 | read_u16_le EOF エラー | crate internal helper for LSB-first formats | ✅ | `test_read_u16_le_eof` |
| 27 | peek_bits EOF ゼロパディング | crate internal helper for LSB-first formats | ✅ | `test_peek_bits_zero_padded_at_eof` |

### Error

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 28 | Display 実装 (全7バリアント) | crate internal API contract | ✅ | `test_display_*` (7テスト) |
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
| 36 | Known vector: empty → e3b0c442... | FIPS 180-4 | ✅ | `test_sha256_empty`、`test_sha256_abc`、`test_sha256_two_block` (56B・パディング溢れ)、`test_sha256_million_a`、`test_sha256_incremental`、`test_sha256_padding_boundary` |

### CRC-32C

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 37 | CRC-32C Castagnoli (polynomial 0x1EDC6F41) | Snappy framing format | ✅ | → snappy.md 参照 |

### SHA-1

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 38 | SHA-1 (FIPS 180-4) | FIPS 180-4 | ✅ | `util::sha1` 実装、ZIP AES PBKDF2 鍵導出で使用 |
| 39 | Known vector: empty → da39a3ee... | FIPS 180-4 | ✅ | `test_sha1_empty` |
| 40 | Known vector: "abc" → a9993e36... | FIPS 180-4 | ✅ | `test_sha1_abc`、`test_sha1_two_block` (56B・パディング溢れ)、`test_sha1_million_a`、`test_sha1_padding_boundary` |
| 41 | Incremental update | FIPS 180-4 | ✅ | `test_sha1_incremental` |

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
| 48 | Streaming matches one-shot | xxHash reference | ✅ | `test_xxhash32_streaming_matches_oneshot`、`test_xxhash32_streaming_vs_oneshot`、`test_xxhash32_stripe_boundary` (16B ストライプ境界) |

### AES-256

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 49 | AES-128 / AES-192 / AES-256 (FIPS 197) | FIPS 197 | ✅ | `util::aes256` 実装、7z/ZIP 暗号化で使用。`test_aes256_block_vector`、`test_aes128_block_vector`、`test_aes192_block_vector` (FIPS 197 vectors) |
| 50 | AES-CTR mode (ZIP-compatible) | WinZip AES spec | ✅ | `apply_ctr_zip_compatible()`。`test_ctr_roundtrip`、`test_aes128_ctr_roundtrip`、`test_aes192_ctr_roundtrip`、`test_ctr_block_boundary` (15/16/17、31/32/33B)、`test_ctr_empty` |
| 51 | AES-CBC mode (7zAES) | 7z Methods.txt | ✅ | `decrypt_cbc_truncated()` / `encrypt_cbc_zero_padded()`。`test_cbc_roundtrip_zero_padding`、`test_cbc_rejects_non_block_multiple` (非16倍数拒否)、`test_cbc_rejects_expected_len_beyond_ciphertext`、`test_cbc_empty_plaintext` |

> 注: `util::aes256` は constant-time 実装ではない (逆 S-box がデータ依存の全探索、GF(2^8) ヘルパがデータ依存ループ)。用途はレガシーフォーマット相互運用 (WinZip AES, 7z AES, PEA AES ストリーム) に限定され、タイミングサイドチャネルが問題になる用途には使わないこと。同様に MD5/SHA-1 は暗号学的に弱い・破られているが、レガシー相互運用目的の実装である。

### MD5

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 52 | MD5 メッセージダイジェスト (RFC 1321) | RFC 1321 | ✅ | `util::md5` 実装、lrzip file-level integrity verification で使用 |
| 53 | RFC 1321 §A.5 既知ベクター | RFC 1321 | ✅ | `test_md5_empty`, `test_md5_abc`, `test_md5_message_digest`, `test_md5_a_to_z`, `test_md5_alphanumeric`, `test_md5_digits_repeated` |
| 54 | Incremental update (multi-block) | RFC 1321 | ✅ | `test_md5_incremental` |

### SHA-512 / Whirlpool / PBKDF2 / EAX

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 55 | SHA-512 メッセージダイジェスト | FIPS 180-4 | ✅ | `util::sha512` (xar/rpm feature)。`test_sha512_empty`, `test_sha512_abc`, `test_sha512_two_block`, `test_sha512_million_a`, `test_sha512_padding_boundary` |
| 56 | Whirlpool-512 メッセージダイジェスト | ISO/IEC 10118-3 / Whirlpool 仕様 (非特許宣言済み) | ✅ | `util::whirlpool` (pea/xar features)。C テーブルは S-box + 巡回行から const fn で生成。`test_whirlpool_empty`, `test_whirlpool_abc`, `test_whirlpool_incremental`, `test_whirlpool_padding_boundary` |
| 57 | PBKDF2 (SHA-1 / Whirlpool) | RFC 2898 + PEA KDF ワイヤ仕様 | ✅ | `util::pbkdf2` (pea feature)。`test_pbkdf2_sha1_rfc6070`、`test_pbkdf2_sha1_4096_iterations`、`test_pbkdf2_whirlpool`、`test_pbkdf2_sha1_xkey_layout`、`test_pbkdf2_out_len_boundaries` (0/19/20/21、40/41)、`test_hmac_sha1_rfc2202`、`test_hmac_long_key`、`test_hmac_block_size_key_boundary` (64/65B 鍵) |
| 58 | AES-EAX 認証付き暗号 (OMAC1 + CTR) | EAX (Bellare-Rogaway-Wagner) + SP 800-38A/38B | ✅ | `util::eax` (pea feature)。`test_eax_paper_vectors`, `test_eax_gladman_vectors`, `test_eax_rejects_bad_tag` |

### その他ユーティリティ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 59 | CRC-16/ARC (poly 0x8005 reflected) | CRC-16/ARC 規約 | ✅ | `util::crc16` (lha/arc features)。`check_value` |
| 60 | CRC-16/CCITT + AUG バリアント | CRC-16/CCITT 規約 | ✅ | `util::crc16ccitt` (macbinary/binhex features)。`check_value`, `augmented` |
| 61 | 出力サイズ上限チェック (decompression bomb 防御) | crate internal | ✅ | `util::bounded::check_output_limit` (feature 非依存)。`within_limit`、`at_exact_limit`、`exceeds_limit`、`no_limit`、`zero_limit`、`zero_additional_at_limit`、`saturating_overflow`、`zero_at_zero_limit` |
| 62 | Base64 codec (RFC 4648) | RFC 4648 | ✅ | `util::base64` (uuencode feature、POSIX uuencode Base64 アルゴリズム用)。`test_rfc4648_vectors`, `test_roundtrip_binary`, `test_rejects_*` 系 |
| 63 | Subbotin carry-less range coder (LZMA 系エントロピー符号の共有部品) | LZMA spec / de facto | ✅ | `util::range_coder` (lzip/lrzip/xz/sevenz features)。`test_range_coder_roundtrip_*`、`test_encoder_normalizes_after_bit_operations`、`test_decoder_*`、`test_decoder_direct_bits_stream_exhaustion` (正規化バイト枯渇 EOF 境界)、`test_decoder_position_and_finished` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 63 |
| **合計** | **63** |
