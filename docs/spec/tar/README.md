# POSIX.1-2017 UStar / GNU / PAX (tar)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [POSIX.1-2017 / IEEE Std 1003.1](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) の tar ヘッダー仕様および [GNU tar manual "Formats"](https://www.gnu.org/software/tar/manual/html_node/Formats.html) に準拠 (ローカルスナップショット: `docs/spec/sources/posix_pax_9699919799.html` / `gnu_tar_formats.html` / `gnu_tar_basic.html` / `gnu_tar_extensions.html` / `gnu_tar_sparse_formats.html`) |
| 参照実装 | GNU tar (GNU sparse は `sparse.c` 実測準拠の動作参照)、system `tar` (oracle — `test_tar_*_system_compat`、`test_tar_gnu_sparse_oracle` 等)。詳細: THIRD_PARTY_NOTICES tar 項・test-fixture provenance 記述 |
| current scope | decoder は UStar / GNU 拡張 / PAX 拡張を自動認識し、encoder は GNU モード (デフォルト) と PAX モードを選択可能 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| v7 (POSIX.1-1988 基本ヘッダ) | [POSIX.1-1988](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) | ✅ | ✅ | magic フィールドなしの形式として受理 (`is_ustar=false` 時に prefix/uname/gname/dev フィールドを解釈しない) |
| ustar (`ustar\0` / `ustar `) | [POSIX.1-1988](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) / [POSIX.1-2017](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) | ✅ | — | encode は GNU/PAX モードで代替 |
| GNU 拡張 (longname 'L'/'K'、binary size エンコーディング) | [GNU tar 1.x](https://www.gnu.org/software/tar/manual/html_node/Formats.html) | ✅ | ✅ | デフォルト encode モード |
| GNU sparse (旧式 'S' ヘッダ + sparse マップ) | [GNU tar 1.x](https://www.gnu.org/software/tar/manual/html_node/Sparse-Formats.html) | ✅ | ✅ | GNU モードで旧式 'S' 生成可 (PAX モードは GNU.sparse.*) |
| PAX (`x`/`g` 拡張ヘッダ、`GNU.sparse.*` keys) | [POSIX.1-2017](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) | ✅ | ✅ | encode は PAX モード選択で生成 |

要件表の「仕様参照」列は `<バリアントID>: <節/見出し>` 形式で、上表のバリアントに対応づける (全バリアント共通の要件は `共通:` プレフィックス)。

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | 512バイトヘッダーパース | POSIX.1-2017 ustar header/data layout | ✅ | `test_tar_header_parse_direct`, `test_tar_header_ustar_prefix_parse_direct` |
| 2 | 8進ASCII フィールド (mode, uid, gid, size) | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_parse_octal` |
| 3 | NUL終端/スペースパディング文字列 | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_parse_str` |
| 4 | ヘッダーチェックサム検証 (符号なし) | POSIX.1-2017 ustar header/data layout | ✅ | `test_tar_header_parse_direct` |
| 5 | ヘッダーチェックサム不一致エラー | POSIX.1-2017 ustar header/data layout | ✅ | `test_tar_header_checksum_mismatch` |
| 6 | ヘッダーチェックサム検証 (符号付き) | POSIX.1-2017 ustar header/data layout | ✅ | `test_tar_header_signed_checksum_fallback` |
| 7 | ファイルタイプ ('0'=通常, '5'=ディレクトリ等) | POSIX.1-2017 ustar header/data layout | ✅ | `test_file_type` |
| 8 | 512バイトブロック境界パディング | POSIX.1-2017 ustar header/data layout | ✅ | `test_round_up_to_block` |
| 9 | EOF検出 (ゼロブロック×2) | POSIX.1-2017 ustar header/data layout | ✅ | `test_decode_empty_archive`、`test_single_zero_block_eof`、`test_decode_truncated_prefix_invariant` (任意の切断位置でエラーまたは正当なエントリ接頭辞) |
| 10 | GNU long name 拡張 ('L'タイプ) | GNU tar extensions | ✅ | `test_gnu_long_name`, `test_pax_and_gnu_longname_priority` |
| 11 | 単一ファイルアーカイブ | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_tar_decode_single_file` |
| 12 | 複数ファイルアーカイブ | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_tar_decode_multi_file` |
| 13 | ディレクトリエントリ | POSIX.1-2017 ustar header/data layout | ✅ | `test_roundtrip_directory` |
| 14 | 空ファイル | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_roundtrip_multiple_files` (空ファイル含む) |
| 15 | 空アーカイブ (ゼロブロック×2のみ) | POSIX.1-2017 ustar header/data layout | ✅ | `test_decode_empty_archive` |
| 16 | エンコード→デコード ラウンドトリップ | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_roundtrip_single_file`, `test_roundtrip_multiple_files`, `test_roundtrip_directory` |
| 17 | UStar マジック `ustar\0` | POSIX.1-2017 ustar header | ✅ | `test_tar_header_ustar_prefix_parse_direct` |
| 18 | 大きなファイルサイズ (バイナリエンコーディング) | GNU tar extensions | ✅ | `test_binary_size_encoding` |
| 19 | シンボリックリンク | POSIX.1-2017 ustar header/data layout | ✅ | `test_roundtrip_symlink` |
| 20 | ハードリンク | POSIX.1-2017 ustar header/data layout | ✅ | `test_roundtrip_hardlink`, `test_file_type` |
| 21 | 特殊ファイル (デバイス、FIFO等) | POSIX.1-2017 ustar header/data layout | ✅ | `test_roundtrip_fifo`, `test_roundtrip_char_device`, `test_roundtrip_block_device`, `test_devmajor_devminor_roundtrip` |
| 22 | owner/group 名 | POSIX.1-2017 ustar header/data layout | ✅ | `test_owner_group_names` |
| 23 | PAX 拡張ヘッダー (`'x'`タイプ) | POSIX.1-2017 pax extended header | ✅ | `test_pax_header_applied`, `test_parse_pax_attributes` |
| 24 | PAX 属性: path, linkpath, size, uid, gid, uname, gname, mtime, mode | POSIX.1-2017 pax extended header | ✅ | `test_pax_header_applied`, `test_pax_mode_applied`, `test_pax_mode_overflow_roundtrip`, `test_pax_long_uname_gname_roundtrip` ほか |
| 25 | GNU sparse PAX 属性: `GNU.sparse.name/size/realsize/numblocks/map` | GNU tar PAX sparse extensions | ✅ | `test_apply_pax_sparse_map`, `test_pax_sparse_roundtrip` |
| 26 | PAX 負 timestamp decode (`mtime`) | POSIX.1-2017 pax extended header | ✅ | `test_pax_negative_mtime`, `test_pax_negative_fractional_time` |
| 27 | PAX グローバルヘッダー (`'g'`タイプ): keyword 単位で後続の 'g' が override し、未指定 key は保持される | POSIX.1-2017 pax extended header | ✅ | `test_pax_global_header_applied`, `test_pax_per_entry_overrides_global`, `test_global_pax_headers_merge_per_key` |
| 28 | GNU long link 拡張 ('K'タイプ) | GNU tar extensions | ✅ | `test_gnu_long_link` |
| 29 | エンコーダー: 100文字超ファイル名の自動 GnuLongName 生成 | GNU tar extensions | ✅ | `test_roundtrip_long_name` |
| 30 | エンコーダー: 100文字超リンク名の自動 GnuLongLink 生成 | GNU tar extensions | ✅ | `test_roundtrip_long_link_name`, `test_roundtrip_long_name_and_link` |
| 31 | 切り詰めアーカイブエラー (ヘッダーのみ) | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_truncated_archive_header_only` |
| 32 | 100バイト丁度のファイル名 | POSIX.1-2017 ustar / GNU / PAX | ✅ | `test_exact_100_byte_filename` |
| 33 | PAX 不正属性の安全なスキップ | POSIX.1-2017 pax extended header | ✅ | `test_pax_malformed_graceful`, `test_parse_pax_attributes_invalid_length_safely_skipped`, `test_parse_pax_attributes_empty_value`, `test_parse_pax_attributes_short_length`, `test_fuzz_regression_tar_gnu_corrupt`, `test_fuzz_regression_tar_ustar_corrupt`, `test_fuzz_regression_tar_pax_corrupt` |

| 34 | devmajor/devminor フィールド (bytes 329-344) | POSIX.1-2017 ustar header fields | ✅ | `test_devmajor_devminor_roundtrip` |
| 35 | UStar フィクスチャデコード (`tar --format=ustar` 生成) | POSIX.1-2017 ustar header | ✅ | `test_tar_decode_ustar_fixture` (統合テスト) |
| 36 | GNU long name フィクスチャデコード (142バイトパス) | GNU tar extensions | ✅ | `test_tar_decode_gnu_longname_fixture` (統合テスト) |
| 37 | PAX フィクスチャデコード (`tar --format=posix` 生成) | POSIX.1-2017 pax extended header | ✅ | `test_tar_decode_pax_fixture` (統合テスト) |
| 38 | GNU モード長名ラウンドトリップ (>100バイト) | GNU tar extensions | ✅ | `test_tar_gnu_longname_roundtrip` (統合テスト) |
| 39 | PAX モードエンコード→デコード ラウンドトリップ | POSIX.1-2017 pax extended header | ✅ | `test_tar_pax_roundtrip` (統合テスト) |
| 40 | PAX モード長名ラウンドトリップ (>100バイト) | POSIX.1-2017 pax extended header | ✅ | `test_tar_pax_longname_roundtrip` (統合テスト) |
| 41 | GNU モード出力のシステム tar 互換性 | GNU tar extensions | ✅ | `test_tar_gnu_system_compat` (統合テスト) |
| 42 | PAX モード出力のシステム tar 互換性 | POSIX.1-2017 pax extended header | ✅ | `test_tar_pax_system_compat` (統合テスト; 長い path/uname/gname を含む) |
| 43 | PAX エンコーダー: レコード長自己参照計算 | POSIX.1-2017 pax extended header | ✅ | `test_format_pax_record`, `test_format_pax_record_digit_boundary` (ユニットテスト) |
| 44 | PAX エンコーダー: ナノ秒タイムスタンプ (mtime/atime/ctime) | POSIX.1-2017 pax extended header (`atime`; `ctime` は GNU/SCHILY 拡張 keyword) | ✅ | `test_pax_mtime_nanoseconds`, `test_pax_atime_ctime`, `test_format_pax_time` (ユニットテスト) |
| 45 | PAX エンコーダー: 負 timestamp (整数/小数) | POSIX.1-2017 pax extended header | ✅ | `test_pax_negative_mtime_roundtrip`, `test_pax_negative_fractional_mtime_roundtrip`, `test_format_pax_time` |
| 46 | エンコーダー: GNU sparse 書き出し — PAX モードは GNU.sparse.* hybrid (numblocks は v0.1 系、map は v1.0 系の key。`GNU.sparse.major/minor` は出力しない)、GNU モードは旧式 'S' ヘッダ + ext sparse blocks (各 segment は 512B 境界開始 + (realsize,0) terminator) | GNU tar Sparse-Formats (sparse.c 実測準拠) | ✅ | `test_pax_sparse_roundtrip`, `test_pax_sparse_rejects_invalid_layout`, `test_gnu_sparse_rejects_oversize`, `test_tar_gnu_sparse_roundtrip`, `test_tar_gnu_sparse_extended_map`, `test_tar_gnu_sparse_long_name`, `test_tar_gnu_sparse_oracle` (GNU tar 展開) |
| 47 | PAX エンコーダー: 長いパス/リンク名の拡張ヘッダー生成 | POSIX.1-2017 pax extended header | ✅ | `test_pax_long_name`, `test_pax_long_link`, `test_pax_long_name_and_link` (ユニットテスト) |
| 48 | PAX エンコーダー: 複合属性 (長パス+タイムスタンプ) | POSIX.1-2017 pax extended header | ✅ | `test_pax_combined_long_name_and_timestamps` (ユニットテスト) |
| 49 | PAX エンコーダー: TarFormat::Gnu/Pax 切り替え | POSIX.1-2017 pax extended header | ✅ | `test_pax_format_accessor` (ユニットテスト) |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 50 | Typeflag '6' (FIFO): size must be 0 | POSIX.1-2017 | ✅ | `test_roundtrip_fifo` |
| 51 | Typeflag '7' (contiguous/reserved) | POSIX.1-2017 | ✅ | `test_file_type` で FileType::Contiguous |
| 52 | UStar prefix field (155B): path = prefix + "/" + name で再構成 | POSIX.1-2017 ustar | ✅ | `test_tar_header_ustar_prefix_parse_direct` |
| 53 | PAX keyword: charset | POSIX.1-2017 pax | ✅ | `pax_charset` フィールド、`test_pax_charset_comment_hdrcharset_roundtrip` |
| 54 | PAX keyword: comment | POSIX.1-2017 pax | ✅ | `pax_comment` フィールド、`test_pax_charset_comment_hdrcharset_roundtrip` |
| 55 | PAX keyword: hdrcharset | POSIX.1-2017 pax | ✅ | `pax_hdrcharset` フィールド、`test_pax_charset_comment_hdrcharset_roundtrip` |
| 56 | PAX record: UTF-8 encoding 必須 | POSIX.1-2017 pax | ✅ | UTF-8 として処理 |
| 57 | Numeric field overflow: binary encoding fallback (GNU) | GNU tar extensions | ✅ | item 18 |
| 58 | GNU 'S' typeflag (sparse in-header, old style) | GNU tar extensions | ✅ | `FileType::GnuSparse`, `parse_gnu_sparse_entries()`, `test_gnu_sparse_in_header_decode` |
| 59 | GNU binary mtime encoding (base-256、octal 範囲超 / 負の timestamp 用) | GNU tar extensions | ✅ | decode は `parse_octal_i64` で符号付き (two's complement) base-256 を受理 — `test_negative_base256_mtime`。encode 側は GNU モードで負 mtime を PAX record に逃がし、ustar field には 0 を書く |
| 60 | PAX extended header: `<value>` がゼロ長の場合、同名の ustar ヘッダ値・先行 x レコード値・グローバル値を delete する | POSIX.1-2017 pax extended header | ✅ | `effective_pax_attrs` で空 value の属性を削除 (POSIX: ustar ヘッダ値へフォールバック)、後続レコードによる override も last-wins で正規化。`test_pax_empty_value_deletes_attribute` |
| 61 | typeflag `'\0'` は regular file として認識。未認識 typeflag は `FileType::Other(u8)` として保持 | POSIX.1-2017 ustar | ✅ | `from_byte(0)` → Regular、`test_file_type` |
| 62 | 非データ typeflag ('2'-'6') の size field は読み取り時に無視 (data 無し) | POSIX.1-2017 pax.html "No data logical records are stored for types 1, 2, or 5" + types 3/4/6 "no data logical records shall be stored on the medium" (typeflag 6 は size "shall be ignored when reading") | ✅ | `test_nonzero_size_directory_does_not_desync` — 非ゼロ size を持つ dir で次ヘッダにデシンクしない |
| 63 | GNU 非移植 typeflag ('D' dump dir, 'V' volume, 'M' multi-volume, 'N' obsolete longname 等) | GNU tar Formats | ⚠️ | **intentional scope**: `FileType::Other(u8)` としてパース・保持するが semantics は未実装 (decode 時に data は typeflag 規則通り処理) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 62 |
| ⚠️ 一部対応/条件付き | 1 |
| ❌ 未対応 | 0 |
| **合計** | **63** |
