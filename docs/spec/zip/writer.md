# ZIP — エンコーダー / streaming writer

## エンコーダー / Streaming Writer

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 136 | Local + CD + EOCD 完全な構造書き出し | §4.3.7/12/16 | ✅ | `test_roundtrip_multiple_entries_and_comment` |
| 137 | ZIP64 書き出し (auto / force_zip64) | §4.3.14/15, §4.5.3 | ✅ | `test_force_zip64_roundtrip`, `test_zip_force_zip64_system_unzip_compat` |
| 138 | Data Descriptor write (bit 3 + signature) | §4.3.9, §4.4.4 | ✅ | `test_roundtrip_data_descriptor_single_file` |
| 139 | ZipStreamWriter: unknown-size entry streaming | crate API | ✅ | `test_zip_stream_writer_system_unzip_compat` |
| 140 | Decoded entry 再エンコード (metadata 保持) | crate API | ✅ | `test_zip_add_entry_roundtrip_preserves_metadata` |
| 141 | Archive comment 書き出し | §4.3.16 | ✅ | `set_archive_comment()`, `test_archive_comment_roundtrip` |
| 158 | streaming writer の central directory record: `version_made_by` は上位 host byte + 下位 spec version、`version_needed` は最小抽出 version | §4.3.12 | ✅ | `write_streamed_central_directory_record` は `version_made_by` (host byte | version) と `version_needed` を正しく出力。`test_streamed_central_version_made_by` |

---
