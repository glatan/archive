# Snappy

| 項目 | 内容 |
|------|------|
| raw format 仕様 | Google snappy [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt) |
| framing format 仕様 | Google snappy [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt) |
| 参照実装 | なし (書面仕様のみに基づいて実装) |
| current scope | raw block format (varint preamble + 4 種タグ) と framing format (stream identifier + chunk types + CRC-32C) の両方を encode/decode 対象にする |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| raw block format | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt) | ✅ | ✅ | varint preamble + 4 種タグ |
| framing format | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt) | ✅ | ✅ | `sNaPpY` + chunked + CRC-32C |

### Raw block format

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | Preamble: varint-encoded uncompressed length | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Preamble | ✅ | `decode_raw()` で検証、`test_decode_raw_literal_only` |
| 2 | Tag byte bits 0-1: element type (00=literal, 01=copy-1, 10=copy-2, 11=copy-4) | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Element type | ✅ | 全 raw テストで検証 |
| 3 | Literal tag (00): bits 2-7 で長さ 0-59 は直接、60-63 は 1-4 バイト拡張 | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Literal (tag type 00) | ✅ | `test_decode_raw_literal_only`, `test_encode_raw_literal_only` |
| 4 | Copy-1 tag (01): 3-bit length (bits 2-4) + 3-bit offset high (bits 5-7) + 1-byte offset low | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy with 1-byte offset (01) | ✅ | `test_decode_raw_copy` |
| 5 | Copy-2 tag (10): 6-bit length (bits 2-7) + 2-byte LE offset | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy with 2-byte offset (10) | ✅ | `test_roundtrip_raw_repeated` |
| 6 | Copy-4 tag (11): 6-bit length (bits 2-7) + 4-byte LE offset | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy with 4-byte offset (11) | ✅ | `test_decode_raw_copy4` |
| 7 | Copy offset=0 reject | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy semantics | ✅ | `test_decode_raw_invalid_offset` |
| 8 | Overlapping copy (offset < length) | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy semantics | ✅ | `test_decode_raw_copy`, `test_roundtrip_raw_repeated` |
| 9 | Raw roundtrip | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): overall | ✅ | `test_roundtrip_raw_repeated`, `test_snappy_raw_roundtrip` |

### Framing format

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 10 | Stream identifier chunk: type 0xFF, payload `sNaPpY` (6 bytes) | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Stream identifier | ✅ | `test_decode_framed_uncompressed` |
| 11 | Stream identifier must appear first | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Stream identifier | ✅ | `test_decode_framed_skippable_before_identifier_rejected` |
| 12 | Duplicate stream identifier rejected | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Stream identifier | ✅ | `test_decode_framed_duplicate_identifier_rejected`。intentional: 仕様は ignore を推奨 (should) するが、strict validation として reject |
| 13 | Chunk header: 1-byte type + 3-byte LE length | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Chunk format | ✅ | 全 framed テストで検証、`test_decode_framed_truncated_at_every_position` (identifier のみは空フレームとして受理、それ以外の全切断位置で拒否) |
| 14 | Compressed data chunk (type 0x00): masked CRC-32C (4B) + compressed payload | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Compressed data (0x00) | ✅ | `test_roundtrip_framed_large` |
| 15 | Uncompressed data chunk (type 0x01): masked CRC-32C (4B) + raw payload | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Uncompressed data (0x01) | ✅ | `test_decode_framed_uncompressed` |
| 16 | Skippable chunks (types 0x80-0xFE): identifier 後のみ許可 | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Reserved skippable chunks | ✅ | `test_decode_framed_skippable_chunk`, `test_decode_framed_skippable_before_identifier_rejected` |
| 17 | Unskippable reserved chunks (types 0x02-0x7F): reject | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Reserved unskippable chunks | ✅ | デコーダーで reject |
| 18 | Max uncompressed chunk size: 65,536 bytes | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Compressed data (0x00) | ✅ | エンコーダーで `MAX_CHUNK_SIZE = 65_536` として適用 |
| 19 | Framed empty input reject | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Stream identifier | ✅ | `test_decode_framed_empty_rejected` |
| 20 | Framed roundtrip | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): overall | ✅ | `test_roundtrip_framed_empty`, `test_roundtrip_framed_large`, `test_snappy_roundtrip` |

### CRC-32C (Castagnoli)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 21 | Polynomial 0x1EDC6F41 (reversed: 0x82F63B78) | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): CRC-32C checksum | ✅ | `crc32c.rs` 実装の const テーブル |
| 22 | 初期値 0xFFFFFFFF / 最終 XOR 0xFFFFFFFF | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): CRC-32C checksum | ✅ | `Crc32c::new()` / `finish()` |
| 23 | Masked CRC: `((crc >> 15) \| (crc << 17)) + 0xA282EAD8` | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Checksum masking | ✅ | `mask_crc32c()` / `unmask_crc32c()` |
| 24 | Known vector: CRC-32C(`"123456789"`) = `0xE3069283` | CRC-32C reference | ✅ | `test_crc32c_known_vector` |
| 25 | Incremental update | CRC-32C reference | ✅ | `test_crc32c_incremental` |
| 26 | CRC mismatch detection | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Checksum verification | ✅ | `test_decode_framed_bad_crc` |

### エンコーディング詳細 (未記載分)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 27 | Varint encoding: 7-bit chunks, MSB continuation bit (LEB128-style) | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Preamble | ✅ | encode/decode 実装 |
| 28 | Literal 長 60-63 拡張: 60=1B(+1), 61=2B LE(+1), 62=3B LE(+1), 63=4B LE(+1) | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Literal tag | ✅ | `test_decode_raw_literal_length_extension_boundaries` |
| 29 | Copy-1 length = (bits 2-4) + 4, range 4-11 | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy-1 | ✅ | encode/decode 実装 |
| 30 | Copy-2 length = (bits 2-7) + 1, range 1-64 | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy-2 | ✅ | encode/decode 実装 |
| 31 | Copy-4 length = (bits 2-7) + 1, range 1-64 | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy-4 | ✅ | encode/decode 実装 |
| 32 | Framing: compressed chunk max payload ~76,490B (65,536 * ~1.17) | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt): Compressed data | ✅ | エンコーダーで chunk 分割 |
| 33 | Copy-1 max offset: 2047 (11 bits) / Copy-2 max offset: 65535 (u16) / Copy-4 max offset: u32 | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Copy tags | ✅ | フィールド幅で暗黙的 |
| 34 | Preamble varint max decoded length: 2^32 - 1 | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt): Preamble | ✅ | preamble varint > 2^32-1 は `Error::InvalidData` で reject。宣言長の確保に失敗したときも `InvalidData` (`snappy: uncompressed size too large`) |
| 35 | Padding chunk (0xFE): データ内容を検証しない | [`framing_format.txt`](https://raw.githubusercontent.com/google/snappy/main/framing_format.txt) §4.4 | ✅ | skippable chunk として読み飛ばし (0x80..=0xFE の range に包含) |
| 36 | copy offset > 現在の出力位置は不正 ("not allowed") | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt) §2.2 | ✅ | `decode.rs:180` `offset > output.len()` で reject |
| 37 | preamble 達成後の trailing bytes reject | [`format_description.txt`](https://raw.githubusercontent.com/google/snappy/main/format_description.txt) | ✅ | `decode.rs:139` + `test_snappy_raw_decode_rejects_trailing_bytes` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 37 |
| ⚠️ 部分実装  | 0 |
| **合計** | **37** |
