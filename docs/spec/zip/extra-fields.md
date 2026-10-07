# ZIP — extra fields / エンコーディング拡張

## §4.5 Extra Fields

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 91 | Extra field 構造: Header ID (2B) + Data Size (2B) + Data | §4.5.1 | ✅ | パーサーで iterate |
| 92 | Header ID 0x0001: ZIP64 Extended Information | §4.5.3 | ✅ | `test_decode_zip64_sizes_and_offsets` |
| 93 | Header ID 0x0001: Local Header は original + compressed 必須 | §4.5.3 | ✅ | Local/CD 両方で parse |
| 94 | Header ID 0x0007: AV Info | §4.5.2 | ✅ | extra field パーサーが未知 ID として正しくスキップ |
| 95 | Header ID 0x000a: NTFS (Mtime/Atime/Ctime) | §4.5.5 | ✅ | decode: `ZipHeader.ntfs_mtime/atime/ctime` に公開。encode: 書き込み対応。`test_ntfs_timestamp_roundtrip` |
| 96 | Header ID 0x000d: UNIX (Atime/Mtime/Uid/Gid) | §4.5.7 | ✅ | decode: `ZipHeader.unix_uid/gid` に公開。encode: 書き込み対応 (uid/gid + unix_atime/mtime 設定時は AcTime/ModTime に実値)。`test_unix_uid_gid_roundtrip`, `test_unix_extra_field_times` |
| 97 | Header ID 0x0017: Strong Encryption Header | §4.5.12 | ✅ | パースのみ (検出用)。復号は intentional non-support (APPNOTE §10.1)。`test_parse_strong_encryption_extra_aes256`, `test_parse_strong_encryption_extra_3des` |
| 98 | Header ID 0x5455: extended timestamp (Info-ZIP) | §4.6 third-party | ✅ | decode: `ZipHeader.unix_mtime/atime` に公開。encode: 書き込み対応。`test_unix_timestamp_roundtrip` |
| 99 | Header ID 0x7075: Info-ZIP Unicode Path | §4.6.9 | ✅ | decode: `ZipHeader.unicode_path` に公開。encode: extra field 0x7075 書き込み対応 |
| 100 | Header ID 0x9901: WinZip AES | Appendix E | ✅ | `test_roundtrip_aes_encrypted_single_file` |
| 101 | 未知 extra field: スキップ (round-trip しない) | §4.5 | ✅ | パーサーで skip |
| 157 | Header ID 0x000b/0x000c (OS/2 Extended Attributes / OpenVMS)、0x0009 (OS/2 ACL)、0x000f (Patch Descriptor)、0x0018 (Record Management Controls)、0x0065/0x0066 (IBM S/390・AS/400)、0x4690 (POS) 等のシステム固有 extra field、および §4.6 third-party ID (0x2605/0x2705/0x2805 ZipIt、0x4b46 FWKCS MD5、0xa220 MS) の意味解釈 | §4.5.2, §4.5.8-4.5.10, §4.6 | ❌ intentional scope | 未知 ID として読み飛ばし (#101)。ホスト固有属性は `external_attributes` で独立に保持。証明書系 ID (0x0014-0x0016 PKCS#7、0x0019、0x0021-0x0023 Smartcrypt) は Strong Encryption exclusion (README #24) の傘下 |
| 153 | ZIP64 extra field: conditional presence (sentinel 値の場合のみ出現) | §4.5.3 | ✅ | `parse_zip64_extra()` で `need_compressed`/`need_uncompressed`/`need_offset` フラグで制御 |
| 154 | Unicode Comment Extra Field (0x6375) | §4.6.8 | ✅ | decode: `ZipHeader.unicode_comment` に公開。encode: `ZipEntryOptions.unicode_comment` で 0x6375 書き込み対応。`test_unicode_comment_roundtrip`, `test_reencode_preserves_extra_fields` |

---

## Appendix D — Language Encoding (EFS)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 111 | Bit 11 unset → CP437 | Appendix D.2 | ✅ | `test_decode_cp437_name_and_comment` |
| 112 | Bit 11 set → UTF-8 (Unicode ≥ 4.1.0) | Appendix D.2 | ✅ | `test_zip_utf8_metadata_roundtrip_via_reader` |
| 113 | UTF-8 に BOM を含めない | Appendix D.2 | ✅ | BOM なしで出力 |
| 114 | Header ID 0x0008: Extended Language Encoding | Appendix D.5 | ✅ | extra field パーサーが未知 ID として正しくスキップ |
| 115 | Invalid UTF-8 reject (bit 11 set 時) | Appendix D | ✅ | `test_decode_invalid_utf8_metadata_rejected` |

---
