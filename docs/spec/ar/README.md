# ar (GNU/BSD)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [IEEE Std 1003.1-2017 (Issue 7)](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ar.html) (POSIX) ar 形式 / [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) 拡張 / [BSD ar](https://man.freebsd.org/cgi/man.cgi?ar(5)) 拡張 (ローカルスナップショット: `docs/spec/sources/posix_ar_9699919799.html` / `ar_5_freebsd.html` / `gnu_ar_binutils.html`)。注意: POSIX Issue 8 (1003.1-2024) では ar ページが "The archive format is not described" に改訂されフォーマット記述が削除されたため、wire format の正本は Issue 7 + BSD/GNU 実装文書を維持する |
| 参照実装 | GNU binutils ar (GPL-3.0-or-later、thin fixture 生成および system `ar` による oracle・性能比較 `docs/bench/`)、bsdtar (oracle)。詳細: THIRD_PARTY_NOTICES ar 項 |
| 形式概要 | 8B グローバルヘッダー + 60B 固定長メンバーヘッダー × N。圧縮なし、チェックサムなし |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| POSIX 共通 (60B 固定長メンバーヘッダ) | [IEEE Std 1003.1](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ar.html) | ✅ | ✅ | 短い名前のみ |
| GNU 拡張 (`//` 文字列テーブル、`/offset`、`/<n>`) | [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) | ✅ | ✅ | 長い名前の既定エンコード |
| GNU thin (`!<thin>\n`) | [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) | ✅ | ✅ | `ArEncoder::new_thin()` (GNU 方言のみ) |
| BSD 拡張 (`#1/<len>` 名前埋め込み) | [BSD ar](https://man.freebsd.org/cgi/man.cgi?ar(5)) | ✅ | ✅ | 16文字超 or スペース含有名 |

### 共通フォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | グローバルヘッダー `!<arch>\n` (8B) 検証 | IEEE Std 1003.1: ar magic string | ✅ | `decode()` 冒頭で検証、`test_decode_short_gnu_archive` |
| 2 | 60B 固定長メンバーヘッダー: ar_name[16] / ar_date[12] / ar_uid[6] / ar_gid[6] / ar_mode[8] / ar_size[10] / ar_fmag[2] | IEEE Std 1003.1: ar member header fields | ✅ | `test_decode_short_gnu_archive` |
| 3 | ar_fmag (bytes 58-59): `` `\n`` (backtick + newline) 検証 | IEEE Std 1003.1: ar_fmag field | ✅ | `test_ar_decode_rejects_invalid_header_trailer` |
| 4 | ar_date: 10進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_decimal_field()` |
| 5 | ar_uid / ar_gid: 10進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_decimal_field()` |
| 6 | ar_mode: 8進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_octal_field()` |
| 7 | ar_size: 10進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_decimal_field()` / `parse_decimal_str()` |
| 8 | 奇数長エントリの `\n` パディング (2B アラインメント) | IEEE Std 1003.1: ar file alignment | ✅ | `test_decode_odd_sized_entry_padding`、`test_decode_truncated_prefix_invariant` (任意の切断位置でエラーまたは正当なエントリ接頭辞) |

### GNU 拡張

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 9 | シンボルテーブル (`/` エントリ) のスキップ | GNU ar: symbol table (ar_name = `/`) | ✅ | decode.rs の identifier 判定 (`/` `/SYM64/` `__.SYMDEF` 系) でスキップ |
| 10 | 文字列テーブル (`//` エントリ) のパースと保持。要素は `/\n` 終端・要素間パディングなし | GNU ar / ar(5): string table (ar_name = `//`) | ✅ | `test_decode_gnu_string_table` |
| 11 | 長名参照 (`/offset`): 文字列テーブルからのオフセット解決 | GNU ar: extended name reference | ✅ | `test_decode_gnu_string_table`, `test_ar_gnu_system_compat` |
| 12 | 短名 (`name/`): trailing `/` の除去 | GNU ar: short name convention | ✅ | `test_decode_short_gnu_archive`, `test_ar_roundtrip_gnu` |
| 13 | 文字列テーブル不在で `/offset` 参照を reject | GNU ar: validation | ✅ | `test_decode_missing_string_table_rejected` |
| 14 | GNU エンコーダー: 15文字超 or スペース含有 → 文字列テーブル使用 | GNU ar: encoding threshold | ✅ | `test_roundtrip_gnu_long_name` |

### BSD 拡張

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | 拡張名 (`#1/<len>`): ペイロード先頭に名前データ埋め込み | BSD ar: extended name prefix | ✅ | `test_decode_bsd_long_name`, `test_roundtrip_bsd_long_name` |
| 16 | BSD エンコーダー: 16文字以上 or スペース含有 → `#1/<len>` 使用 (ar(5) の必須閾値は 16B 超だが、16B でも `#1` を使う安全側の選択。`#1` 時の ar_size は名前+データの合算) | BSD ar: encoding threshold | ✅ | `test_roundtrip_bsd_exact_16_byte_name` |

### バリデーションとシステム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | 空ファイル名 reject | ar validation | ✅ | `test_empty_name_rejected` |
| 18 | 改行含有ファイル名 reject | ar validation | ✅ | エンコーダーで reject (encode.rs:333)。`test_newline_in_name_rejected` |
| 19 | system `ar` 生成アーカイブの decode | system interop | ✅ | `test_ar_decode_system_archive` |
| 20 | 自前 GNU archive → system `ar` で一覧可能 | system interop | ✅ | `test_ar_gnu_system_compat` |
| 21 | 自前 BSD archive → `bsdtar` で一覧可能 | system interop | ✅ | `test_ar_bsd_system_compat` |
| 22 | encoder → decoder roundtrip (GNU/BSD 両方言) | roundtrip | ✅ | `test_roundtrip_gnu_short_name`, `test_roundtrip_gnu_long_name`, `test_roundtrip_bsd_long_name`, `test_ar_roundtrip_gnu` |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 23 | BSD symbol table (`__.SYMDEF` / `__.SYMDEF SORTED`) スキップ | [BSD ar](https://man.freebsd.org/cgi/man.cgi?ar(5)) | ✅ | decode.rs の identifier 判定でスキップ (同一パスは `test_sym64_symbol_table_skipped` でカバー) |
| 24 | ar_date / ar_uid / ar_gid: all-space (空) の許容 | implementation leniency | ✅ | パーサーで space trim |
| 25 | Thin archives (`!<thin>\n`): 通常メンバはヘッダのみ (size は実ファイルサイズ、payload 非格納)。`//`・`/` 等の特殊メンバは payload を持つ | GNU ar thin (binutils `ar rcT` 出力で検証) | ✅ | `THIN_MAGIC` 認識、`ArEntry::is_thin`、`test_thin_archive_decode`、`test_ar_decode_gnu_thin_fixture` (実 ar バイト) |
| 26 | 64-bit GNU symbol table (`/SYM64/`) | GNU ar 64-bit | ✅ | identifier 判定でスキップ (`test_sym64_symbol_table_skipped`) |
| 27 | thin encoder: `!<thin>\n` + メンバヘッダのみ emit (size=実ファイルサイズ)。`add_reference` でデータなし参照可 | GNU ar thin | ✅ | `test_thin_roundtrip`、`test_thin_add_file_uses_data_len`、`test_ar_thin_system_list_compat` (system `ar tv`) |
| 28 | 特殊メンバの順序制約 (`/` は先頭、`//` は先頭または `/` 直後、`__.SYMDEF` は先頭) | ar(5): Special Members | ✅ | decoder は位置を問わず identifier 判定でスキップ。順序は emitter 責務であり当該メンバは emit しない (intentional scope) |
| 29 | symbol table 内部形式 (SVR4: BE u32 count + offsets + NUL 名 / BSD: ranlib 構造体配列) のパース | ar(5): Symbol Tables | ❌ | intentional scope (symbol 解決は linker の責務であり archive 層の要件外)。decode は先頭メンバとして検出・スキップのみ |
| 30 | "archive format shall not truncate valid filenames" (長名の保持) | IEEE Std 1003.1: OPERANDS | ✅ | GNU `/offset`・BSD `#1/` の両長名機構で充足 (`test_roundtrip_gnu_long_name`, `test_ar_roundtrip_multiple_long_names_bsd`) |
| 31 | object file 含有時の symbol table 生成・維持 (`ar -s` 相当) | IEEE Std 1003.1: DESCRIPTION / ar(5) | ❌ | intentional scope (utility 層の責務。encoder は symtab を生成しない) |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 29 |
| ⚠️ 部分実装  | 0 |
| ❌ 未実装 (intentional scope)  | 2 |
| **合計** | **31** |
