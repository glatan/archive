# cpio (`odc` / SVR4 `newc` / `newcrc`)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [POSIX.1-2001 cpio/pax](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) (`odc`)。SVR4 `newc` / `newcrc` は [FreeBSD `cpio(5)` man page](https://man.freebsd.org/cgi/man.cgi?cpio(5)) 等の de facto 記述に準拠 (ローカルスナップショット: `docs/spec/sources/posix_pax_9699919799.html` / `cpio_5_freebsd.html`) |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| `odc` (POSIX portable ASCII) | [POSIX.1 cpio](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html) | ✅ | ✅ | 76B header、magic `070707`、パディングなし |
| `newc` (SVR4 ASCII) | SVR4 cpio | ✅ | ✅ | 110B header、magic `070701`、4B align |
| `newcrc` (SVR4 + CRC) | SVR4 cpio | ✅ | ✅ | magic `070702`、data CRC 検証 |
| `bin` (SVR4 binary header) | SVR4 binary cpio | ❌ | ❌ | intentional scope: バイナリヘッダ形式は非対応 |

### テスト対象要件と網羅状況

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | `odc` 76バイト / `newc` 110バイトヘッダーパース | POSIX cpio `odc` format | ✅ | `test_cpio_odc_magic_accepted`, 統合テスト |
| 2 | マジック `070707` / `070701` / `070702` 検証 | POSIX cpio `odc` format | ✅ | `test_cpio_odc_magic_accepted`, `test_cpio_newc_magic_accepted`, `test_cpio_newcrc_magic_accepted` |
| 3 | 不正マジックナンバーエラー | POSIX cpio / SVR4 cpio | ✅ | `test_invalid_cpio_magic` |
| 4 | ヘッダー短すぎエラー | POSIX cpio / SVR4 cpio | ✅ | `test_cpio_header_too_short` |
| 5 | 16進ASCII フィールド | SVR4 cpio `newc` / `newcrc` format | ✅ | `test_parse_hex_field` |
| 6 | `newc/newcrc` の 4バイト境界アラインメント | SVR4 cpio `newc` / `newcrc` format | ✅ | `test_align4` |
| 7 | `odc` の name/data 無パディング配置 | POSIX cpio `odc` format | ✅ | `test_decode_odc_without_newc_padding`, `test_odc_has_no_512_padding` |
| 8 | TRAILER!!! によるEOF検出 | POSIX/SVR4 cpio entry layout | ✅ | `test_decode_trailer_only_archive`, `test_missing_trailer_rejected` |
| 9 | 単一ファイルアーカイブ | POSIX/SVR4 cpio entry layout | ✅ | `test_cpio_decode_single_file`, `test_roundtrip_odc_format` |
| 10 | 複数ファイルアーカイブ | POSIX/SVR4 cpio entry layout | ✅ | `test_roundtrip_multiple_files` |
| 11 | 多数ファイル (10ファイル) | POSIX cpio / SVR4 cpio | ✅ | `test_roundtrip_many_files` |
| 12 | 空ファイル | POSIX cpio / SVR4 cpio | ✅ | `test_roundtrip_multiple_files` |
| 13 | エンコード→デコード ラウンドトリップ | POSIX cpio / SVR4 cpio | ✅ | `test_roundtrip_single/multiple/many_files`, `test_roundtrip_odc_format` |
| 14 | CRC形式 (`070702`) | SVR4 cpio `newc` / `newcrc` format | ✅ | `test_roundtrip_crc_format`, `test_crc_mismatch_detected`, `test_cpio_newcrc_magic_accepted` |
| 15 | シンボリックリンク | POSIX/SVR4 cpio entry layout | ✅ | `test_roundtrip_symlink`, `test_cpio_file_type_helpers` |
| 16 | ディレクトリ | POSIX/SVR4 cpio entry layout | ✅ | `test_roundtrip_directory` |
| 17 | ファイルタイプヘルパー (S_IFREG/S_IFLNK/S_IFDIR) | POSIX cpio / SVR4 cpio | ✅ | `test_cpio_file_type_helpers` |
| 18 | デバイスファイル | POSIX/SVR4 cpio entry layout | ✅ | `test_roundtrip_device` |
| 19 | 不正16進/8進フィールドエラー | POSIX cpio `odc` format | ✅ | `test_invalid_hex_field`, `test_invalid_octal_field` |
| 20 | 空アーカイブ (TRAILERのみ) | POSIX cpio / SVR4 cpio | ✅ | `test_roundtrip_empty_archive` |
| 21 | namesize>=1 (NUL 終端含む) の検証 | POSIX cpio / SVR4 cpio | ✅ | `test_cpio_namesize_zero`, `test_missing_name_null_terminator_rejected` |
| 22 | newc (`070701`) の check フィールドは 0 | SVR4 cpio `newc` / `newcrc` format | ✅ | `test_newc_nonzero_check_rejected` |
| 23 | CRC形式: 空ファイル (check=0) の検証 | SVR4 cpio `newc` / `newcrc` format | ✅ | `test_roundtrip_crc_empty_file` |
| 24 | FIFO (named pipe) ラウンドトリップ | POSIX/SVR4 cpio entry layout | ✅ | `test_fifo_roundtrip` |

### フィールド仕様 (未記載分)

| # | 仕様要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|---------|---------|------|----------------|
| 25 | nlink フィールド (hard link 数) | POSIX cpio / SVR4 newc | ✅ | ヘッダーでパース済み |
| 26 | ino フィールド (inode 番号) | POSIX cpio / SVR4 newc | ✅ | `test_custom_ino` |
| 27 | rdevmajor / rdevminor フィールド (newc/newcrc) | SVR4 newc/newcrc | ✅ | device roundtrip で検証 |
| 28 | mtime フィールド (modification time) | POSIX cpio / SVR4 | ✅ | ヘッダーで読み書き |
| 29 | uid / gid フィールド | POSIX cpio / SVR4 | ✅ | ヘッダーで読み書き |
| 30 | mode フィールド: file type (upper bits) + permission (lower 12 bits) | POSIX cpio / SVR4 | ✅ | `test_cpio_file_type_helpers` |
| 31 | odc field widths: dev(6)/ino(6)/mode(6)/uid(6)/gid(6)/nlink(6)/rdev(6)/mtime(11)/namesize(6)/filesize(11) | POSIX cpio odc | ✅ | パーサーで固定幅読み取り |
| 32 | newc field widths: 各フィールド 8 hex digits | SVR4 newc/newcrc | ✅ | パーサーで固定幅読み取り |
| 33 | newcrc check フィールド: 全データバイトの unsigned sum mod 2^32 | SVR4 newcrc | ✅ | `test_crc_mismatch_detected` |
| 34 | Hard link 検出: ino + dev 一致 | POSIX cpio | ✅ | `is_hard_link()`, `find_hard_link_groups()`, `test_is_hard_link`, `test_find_hard_link_groups` |
| 35 | Socket type (S_IFSOCK = 0140000) | POSIX cpio | ✅ | `S_IFSOCK` 定数、`is_socket()` メソッド、`add_socket()` エンコーダー、`test_socket_roundtrip` |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 35 |
| **合計** | **35** |

