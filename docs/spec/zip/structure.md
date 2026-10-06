# ZIP — ストリーム構造 (local header / central directory / EOCD / ZIP64)

## §4.1-4.2 General Requirements

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 1 | レコードは PK signature で識別 | §4.1.1, §4.2.1 | ✅ | 全 signature 定数で検証 |
| 2 | データ整合性に CRC-32 を使用 | §4.1.5 | ✅ | `test_zip_decode_detects_checksum_mismatch` |
| 3 | 全値は little-endian | §4.3.3 | ✅ | 全 read/write で LE |
| 4 | EOCD が必ず 1 つ存在 | §4.3.1 | ✅ | `find_eocd()` |
| 5 | 各ファイルに Local Header + 対応 CD Header | §4.3.2 | ✅ | Local/CD 整合性検証 |
| 6 | Local Header / EOCD に圧縮適用不可 | §4.3.4 | ✅ | 構造的に圧縮なし |

---

## §4.3.7-4.3.8 Local File Header / File Data

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 7 | Signature `0x04034B50` (4B) | §4.3.7 | ✅ | `test_zip_decode_detects_invalid_local_file_header_signature` |
| 8 | version needed to extract (2B) | §4.3.7, §4.4.3 | ✅ | パース + `ZipHeader.version_needed` に公開 |
| 9 | general purpose bit flag (2B) | §4.3.7, §4.4.4 | ✅ | bit 0,3,11 を使用 |
| 10 | compression method (2B) | §4.3.7, §4.4.5 | ✅ | 0,8,99 を認識 |
| 11 | last mod file time (2B) | §4.3.7, §4.4.6 | ✅ | 読み書き |
| 12 | last mod file date (2B) | §4.3.7, §4.4.6 | ✅ | 読み書き |
| 13 | crc-32 (4B) | §4.3.7, §4.4.7 | ✅ | bit 3 時は 0 |
| 14 | compressed size (4B) | §4.3.7, §4.4.8 | ✅ | ZIP64 override 対応 |
| 15 | uncompressed size (4B) | §4.3.7, §4.4.9 | ✅ | ZIP64 override 対応 |
| 16 | file name length (2B) + file name (variable) | §4.3.7, §4.4.17 | ✅ | UTF-8/CP437 対応 |
| 17 | extra field length (2B) + extra field (variable) | §4.3.7, §4.4.28 | ✅ | 0x0001, 0x9901 認識 |
| 18 | Local と Central の name/flags/method 一致検証 | §4.3.7 / §4.3.12 | ✅ | `test_zip_decode_detects_local_and_central_name_mismatch` |
| 149 | zero-byte file / directory は file data を含まない | §4.3.8 | ✅ | Store + size=0 で処理 |

---

## §4.3.9 Data Descriptor

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 19 | bit 3 set → Data Descriptor 必須 | §4.3.9.1 | ✅ | `test_decode_with_data_descriptor_signature` |
| 20 | Signature `0x08074B50` 付き / なし両対応 | §4.3.9.3 | ✅ | `test_decode_with_data_descriptor_no_signature` |
| 21 | 書き込み時は signature を含める | §4.3.9.4 | ✅ | エンコーダーで常に signature 付き |
| 22 | ZIP64 時は 8B sizes | §4.3.9.2 | ✅ | `test_force_zip64_roundtrip` |
| 23 | 不正 Data Descriptor reject | §4.3.9 | ✅ | `test_bad_data_descriptor_rejected`, `test_zip_decode_detects_data_descriptor_mismatch` |
| 24 | CD Encryption 時の DD field = binary zeros | §4.3.9.6 | ✅ | CD Encryption 対応: bit 13 マスキングで DD field をゼロ扱い。`test_cd_encryption_bit13_masking` |

---

## §4.3.10-11 Archive Decryption Header / Extra Data Record

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 25 | Archive Decryption Header | §4.3.10 | ✅ | `parse_archive_decryption_header` でパース+復号。`test_parse_archive_decryption_header_aes256`, `test_cd_encryption_aes256_decode` |
| 26 | Archive Extra Data Record (sig `0x08064B50`) | §4.3.11 | ✅ | decode 時にシグネチャを認識してスキップ。`test_archive_extra_data_record_skipped` |

---

## §4.3.12 Central Directory File Header

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 27 | Signature `0x02014B50` (4B) | §4.3.12 | ✅ | `test_decode_store_single_file` |
| 28 | version made by (2B): host system + spec version | §4.3.12, §4.4.2 | ✅ | decode: `ZipHeader.host_system` に公開。write: Unix=3/DOS=0 + version |
| 29 | version needed to extract (2B) | §4.3.12, §4.4.3 | ✅ | パース + `ZipHeader.version_needed` に公開 |
| 30 | general purpose bit flag (2B) | §4.3.12 | ✅ | Local と一致検証 |
| 31 | compression method (2B) | §4.3.12 | ✅ | Local と一致検証 |
| 32 | last mod file time/date (2B × 2) | §4.3.12 | ✅ | 読み書き |
| 33 | crc-32 (4B) | §4.3.12 | ✅ | 検証に使用 |
| 34 | compressed size / uncompressed size (4B × 2) | §4.3.12 | ✅ | ZIP64 override 対応 |
| 35 | file name length / extra field length / file comment length (2B × 3) | §4.3.12 | ✅ | 読み書き |
| 36 | disk number start (2B) | §4.3.12, §4.4.13 | ✅ | 0 以外は reject |
| 37 | internal file attributes (2B) | §4.3.12, §4.4.14 | ✅ | `ZipEntry::internal_attributes` / `ZipEntryOptions::internal_attributes` で公開、読み書き |
| 38 | external file attributes (4B) | §4.3.12, §4.4.15 | ✅ | `ZipEntry::external_attributes` / `ZipEntryOptions::external_attributes` で公開、読み書き |
| 39 | relative offset of local header (4B) | §4.3.12, §4.4.16 | ✅ | ZIP64 override 対応 |
| 40 | file name / extra field / file comment (variable) | §4.3.12 | ✅ | UTF-8/CP437 対応 |

---

## §4.3.13 Digital Signature

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 41 | Digital Signature (sig `0x05054B50`) | §4.3.13 | ✅ | decode 時にシグネチャを認識してスキップ。`test_digital_signature_skipped` |

---

## §4.3.14-15 ZIP64 End of Central Directory

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 42 | ZIP64 EOCD Record (sig `0x06064B50`): size, versions, counts, offsets | §4.3.14 | ✅ | `test_force_zip64_roundtrip` |
| 43 | ZIP64 EOCD Locator (sig `0x07064B50`): disk, offset, total_disks | §4.3.15 | ✅ | `test_force_zip64_roundtrip` |
| 44 | ZIP64 EOCD extensible data sector | §4.3.14.3 | ✅ | ZIP64 EOCD パース時に明示的スキップ (size_of_record - 44 bytes) |
| 45 | ZIP64 multi-disk: disk_number / cd_disk_number 検証 | §4.3.14 | ✅ | 単一入力では 0 以外 reject、`decode_parts` では `disk_number == parts-1` かつ `cd_disk_number <= disk_number` を検証 |

---

## §4.3.16 End of Central Directory Record

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 46 | Signature `0x06054B50` (4B) | §4.3.16 | ✅ | `find_eocd()` |
| 47 | 後方検索 (comment length 検証付き) | §4.3.16 | ✅ | `test_decode_with_eocd_comment_backward_search` |
| 48 | disk number / CD disk number (2B × 2) | §4.3.16 | ✅ | 単一入力では 0 以外 reject、`decode_parts` では `disk_number == parts-1` かつ `cd_disk_number <= disk_number` を検証 |
| 49 | total entries (2B) / CD size (4B) / CD offset (4B) | §4.3.16 | ✅ | 0xFFFF/0xFFFFFFFF 時は ZIP64 fallback |
| 50 | .ZIP file comment (variable) | §4.3.16, §4.4.26 | ✅ | デコード時パース済み。エンコード時は `set_archive_comment()` で設定可能 |

---

## §4.4.2 version made by — Host System

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 51 | Upper byte: host system (0=DOS, 3=UNIX, ..., 19=OS X) | §4.4.2 | ✅ | decode: `ZipHeader.host_system` に公開。write: `#[cfg(unix)]` で 3 |

---

## §4.4.3 version needed to extract — Feature Versions

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 52 | version 1.0 (10): Default | §4.4.3 | ✅ | 暗黙的に対応 |
| 53 | version 2.0 (20): Deflate / directories / PKZIP encryption | §4.4.3 | ✅ | write 時のデフォルト |
| 54 | version 4.5 (45): ZIP64 | §4.4.3 | ✅ | ZIP64 時に設定 |
| 55 | version 5.1 (51): AES encryption | §4.4.3 | ✅ | AES 使用時に version_needed=51 で write |
| 56 | version 6.3 (63): LZMA / PPMd | §4.4.3 | ✅ | `compute_version_needed()` で LZMA/PPMd 時に version=63 設定 |
| 57 | feature version に基づく最小バージョン強制 | §4.4.3.1 | ✅ | decode: `ZipHeader.version_needed` に公開。encode: local/central とも `compute_version_needed()` で compression method 考慮 (bzip2=46, deflate64=21, lzma/ppmd=63, aes=51, zip64=45)。`test_bzip2_version_needed_in_local_and_central` |

---

## §4.4.4 General Purpose Bit Flag

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 58 | Bit 0: File is encrypted | §4.4.4 | ✅ | encryption dispatch |
| 59 | Bit 1-2: method-specific flags (Implode/Deflate compression options) | §4.4.4 | ✅ | Implode: bit 1 (8K dict), bit 2 (3 trees) を decode で解釈。Deflate: option 未解釈 (動作に影響なし) |
| 60 | Bit 3: Data Descriptor present | §4.4.4 | ✅ | `test_roundtrip_data_descriptor_single_file` |
| 61 | Bit 4: Enhanced Deflating reserved | §4.4.4 | ✅ | reserved bit、読み飛ばし (仕様通りの動作) |
| 62 | Bit 5: Compressed patched data | §4.4.4 | ✅ | 未サポート機能、読み飛ばし (仕様通りの動作) |
| 63 | Bit 6: Strong encryption | §4.4.4 | ✅ | 検出して `Unsupported` を返す。復号は intentional non-support (APPNOTE §10.1 により実装に PKWARE との別途ライセンス契約が義務付けられているため)。`test_strong_encryption_rejected_aes`, `test_strong_encryption_rejected_other_algorithms` |
| 64 | Bit 11: Language Encoding Flag (UTF-8) | §4.4.4 | ✅ | `test_decode_cp437_name_and_comment`, `test_decode_invalid_utf8_metadata_rejected` |
| 65 | Bit 13: Central Directory Encryption masking | §4.4.4 | ✅ | bit 13 検出時に CRC-32/圧縮サイズ/非圧縮サイズを Local File Header からフォールバック。CD 本体の暗号化 (ADH) は検出して `Unsupported` を返す |
| 66 | Bit 6 set → version ≥ 50, bit 0 も set | §4.4.4 | ✅ | version < 50 と bit 0 未設定を reject |
| 152 | Method 14 (LZMA): general purpose bit 1 = EOS marker 使用 | §4.4.4, §5.8.9 | ✅ | bit 1 set → `lzma_decode_with_props` (EOS marker)、unset → `lzma_decode_with_props_and_size` (サイズベース) |

---

## §4.4.6-4.4.17 Other Fields

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 81 | MS-DOS date/time format (2-second precision, year from 1980) | §4.4.6 | ✅ | 読み書き、変換なし |
| 82 | CRC-32: pre-conditioning 0xFFFFFFFF + post-conditioning complement | §4.4.7 | ✅ | `util::crc32` |
| 83 | bit 3 時 Local Header の CRC/sizes = 0 | §4.4.7, §4.4.8, §4.4.9 | ✅ | Data Descriptor write path |
| 84 | ZIP64: size 0xFFFFFFFF → extra field 0x0001 参照 | §4.4.8, §4.4.9 | ✅ | `test_decode_zip64_sizes_and_offsets` |
| 85 | file name: forward slash のみ、drive letter 不可 | §4.4.17.1 | ✅ | エンコーダーでバックスラッシュ、ドライブレター、パストラバーサル reject。`test_path_validation_*` |
| 86 | file name: NULL 終端ではない (length field で管理) | §4.4.17 | ✅ | length-based parsing |
| 87 | ZIP64: offset 0xFFFFFFFF → extra field 0x0001 参照 | §4.4.16 | ✅ | `test_force_zip64_roundtrip` |
| 88 | ZIP64: disk 0xFFFF → extra field 0x0001 参照 | §4.4.13 | ✅ | `parse_zip64_extra` が `need_disk` で 0x0001 内 disk start (4B) を解決し `disk_start == 0xFFFF` を override。`test_zip64_disk_start_override`, `test_zip64_disk_start_override_missing_field`, `test_zip64_disk_start_override_multidisk` |
| 89 | internal file attributes bit 0 (ASCII text marker) | §4.4.14 | ✅ | `ZipEntry::internal_attributes` で公開 (bit 解釈はアプリケーション側) |
| 90 | external file attributes (host-system dependent) | §4.4.15 | ✅ | `ZipEntry::external_attributes` で公開、任意値 write 可能 |
| 150 | encode 時の auto-ZIP64 promotion (field overflow → 0xFFFF/0xFFFFFFFF 設定) | §4.4.1.4 | ✅ | `needs_zip64_entry()` で自動判定 |
| 151 | compressed_size は decryption header のバイト数を含む | §4.4.8-9 | ✅ | Traditional PKZIP 12B / AES salt+verifier+HMAC 込み |

---

## §8 Splitting and Spanning

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 125 | Multi-disk / split archive | §8 | ✅ | `decode_parts(&[&[u8]])` / `decode_parts_with_password_bytes` が segment を連結し、disk 相対オフセット (entry `disk_start` + local header offset、CD disk、ZIP64 locator/record) を各 segment 開始位置で解決。disk 数と EOCD/ZIP64 disk フィールドの整合を検証、PKZIP spanning signature 0x08074b50 を受理。`split_parts_roundtrip`, `split_parts_real_disk_offsets`, `split_parts_zip64_multidisk`, `split_parts_disk_count_mismatch`, `split_parts_rejects_empty_and_accepts_single`, `split_parts_spanning_signature_tolerated` |
| 155 | ZIP64 EOCD Locator は ZIP64 EOCD record と同一 disk 上に存在すること | §4.3.15 ("MUST reside on the same disk") | ✅ | `decode_parts` の disk 番号整合検証で間接的に保証 (locator disk ≠ EOCD disk は reject) |
| 156 | self-extracting archive (SFX): 先頭の実行可能部を読み飛ばしてアーカイブ開始位置を検出 | APPNOTE 前言 "self-extracting" / de facto | ✅ | `detect_sfx_prefix` および `detect_sfx_prefix_zip64` が EOCD 算術 (eocd_offset − cd_size − cd_offset) でプレフィックス長を推定し、CD・ローカルヘッダー・ZIP64 のオフセットを補正する (`decodes_sfx_prefixed_archive`, `sfx_prefix_via_zip64`) |
| 126 | Record が segment 境界を跨がない | §8.5.2 | — | writer 側のレイアウト制約であり reader は各 record を連結ストリーム上でシークして読むだけのため該当なし |

---

## システム互換

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 142 | system `zip` (Deflate) → crate decode | interop | ✅ | `test_zip_decode_system_deflate_archive` |
| 143 | system `zip -0` (Store) → crate decode | interop | ✅ | `test_zip_decode_system_store_archive` |
| 144 | crate encode → system `unzip` | interop | ✅ | `test_zip_encode_system_unzip_compat` |
| 145 | crate encode (DD) → system `unzip` | interop | ✅ | `test_zip_encode_data_descriptor_system_unzip_compat` |
| 146 | crate Traditional encrypt → system `unzip -P` | interop | ✅ | `test_zip_encode_traditional_system_unzip_compat` |
| 147 | system Traditional encrypt → crate decode | interop | ✅ | `test_zip_decode_system_traditional_encrypted_archive` |
| 148 | crate StreamWriter → system `unzip` | interop | ✅ | `test_zip_stream_writer_system_unzip_compat` |

---
