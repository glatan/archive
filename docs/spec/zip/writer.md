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
| 160 | `ZipEncoder::finish_parts(max_segment_size)` による multi-disk emit: record 境界分割 (LFH/CD/DD/EOCD+ZIP64 尾ブロックは atomic、§8.5.2) + compressed data は境界切断可、disk 相対 `local_header_offset`/CD `disk number start`/EOCD per-disk フィールドを出力 | §8.5 | ✅ | `test_finish_parts_roundtrip`, `test_finish_parts_roundtrip_zip64`, `test_finish_parts_records_not_split`, `test_finish_parts_disk_fields`, `test_finish_parts_single_segment`, `test_finish_parts_data_spans_disks`, `test_finish_parts_too_small`, `test_zip_finish_parts_system_unzip_compat`。spanning signature 0x08074b50 は emit しない (§8.5.3 optional)。§8.5.1 の 64K 最小セグメントは強制しない (atomic record が収まる下限のみ)、disk 数上限は 0xFFFF (16-bit disk field、超過時 `Unsupported`)。`ArjEncoder::finish_parts` と同型、`decode_parts(&[&[u8]])` と入出力対称 |
| 160a | `finish_parts_with(size, &ZipSplitOptions)` の `central_directory_on_last_segment`: CD 全体 + 末尾ブロックを 1 つの atomic unit として最終セグメントに配置 (`cd_disk == this_disk` を保証、CD+tail が 1 セグメントに収まらない場合 `InvalidData`)。Info-ZIP `unzip` は CD が最終 disk で始まらない multi-disk を処理しないための互換レイアウト。default は従来の貪欲配置 (EOCD 単独最終セグメントも emit しうる、§8.5 上は合法) | §8.5 | ✅ | `test_finish_parts_cd_on_last_segment`, `test_finish_parts_cd_on_last_segment_too_small`, `test_zip_finish_parts_system_unzip_compat` (compat 経由)。なお Info-ZIP は multi-disk の **抽出** は一切非対応 (`zip -s` 生成物でも `unzip -p` 不可) のため抽出 oracle は `7z x -so` を使用 |

---
