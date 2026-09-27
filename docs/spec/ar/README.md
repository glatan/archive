# ar (GNU/BSD)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [IEEE Std 1003.1](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ar.html) (POSIX) ar 形式 / [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) 拡張 / [BSD ar](https://man.freebsd.org/cgi/man.cgi?ar(5)) 拡張 (ローカルスナップショット: `docs/spec/sources/posix_ar_9699919799.html` / `ar_5_freebsd.html`) |
| 形式概要 | 8B グローバルヘッダー + 60B 固定長メンバーヘッダー × N。圧縮なし、チェックサムなし |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| POSIX 共通 (60B 固定長メンバーヘッダ) | [IEEE Std 1003.1](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ar.html) | ✅ | ✅ | 短い名前のみ |
| GNU 拡張 (`//` 文字列テーブル、`/offset`、`/<n>`) | [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) | ✅ | ✅ | 長い名前の既定エンコード |
| GNU thin (`!<thin>\n`) | [GNU ar](https://sourceware.org/binutils/docs/binutils/ar.html) | ✅ | ❌ | thin archive の生成は非対応 |
| BSD 拡張 (`#1/<len>` 名前埋め込み) | [BSD ar](https://man.freebsd.org/cgi/man.cgi?ar(5)) | ✅ | ✅ | 16文字超 or スペース含有名 |

### 共通フォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | グローバルヘッダー `!<arch>\n` (8B) 検証 | IEEE Std 1003.1: ar magic string | ✅ | `decode()` 冒頭で検証, `test_decode_short_gnu_archive` |
| 2 | 60B 固定長メンバーヘッダー: ar_name[16] / ar_date[12] / ar_uid[6] / ar_gid[6] / ar_mode[8] / ar_size[10] / ar_fmag[2] | IEEE Std 1003.1: ar member header fields | ✅ | `test_decode_short_gnu_archive` |
| 3 | ar_fmag (bytes 58-59): `` `\n`` (backtick + newline) 検証 | IEEE Std 1003.1: ar_fmag field | ✅ | デコーダーで検証 |
| 4 | ar_date: 10進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_decimal()` |
| 5 | ar_uid / ar_gid: 10進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_decimal()` |
| 6 | ar_mode: 8進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_octal()` |
| 7 | ar_size: 10進 ASCII (右スペースパディング) | IEEE Std 1003.1: ar member header fields | ✅ | `parse_decimal()` |
| 8 | 奇数長エントリの `\n` パディング (2B アラインメント) | IEEE Std 1003.1: ar file alignment | ✅ | `test_decode_odd_sized_entry_padding` |

### GNU 拡張

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 9 | シンボルテーブル (`/` エントリ) のスキップ | GNU ar: symbol table (ar_name = `/`) | ✅ | デコーダーで `is_symbol_table()` 判定 |
| 10 | 文字列テーブル (`//` エントリ) のパースと保持 | GNU ar: string table (ar_name = `//`) | ✅ | `test_decode_gnu_string_table` |
| 11 | 長名参照 (`/offset`): 文字列テーブルからのオフセット解決 | GNU ar: extended name reference | ✅ | `test_decode_gnu_string_table`, `test_ar_gnu_system_compat` |
| 12 | 短名 (`name/`): trailing `/` の除去 | GNU ar: short name convention | ✅ | `test_decode_short_gnu_archive`, `test_ar_roundtrip_gnu` |
| 13 | 文字列テーブル不在で `/offset` 参照を reject | GNU ar: validation | ✅ | `test_decode_missing_string_table_rejected` |
| 14 | GNU エンコーダー: 15文字超 or スペース含有 → 文字列テーブル使用 | GNU ar: encoding threshold | ✅ | `test_roundtrip_gnu_long_name` |

### BSD 拡張

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | 拡張名 (`#1/<len>`): ペイロード先頭に名前データ埋め込み | BSD ar: extended name prefix | ✅ | `test_decode_bsd_long_name`, `test_roundtrip_bsd_long_name` |
| 16 | BSD エンコーダー: 16文字以上 or スペース含有 → `#1/<len>` 使用 | BSD ar: encoding threshold | ✅ | `test_roundtrip_bsd_exact_16_byte_name` |

### バリデーションとシステム互換

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | 空ファイル名 reject | ar validation | ✅ | `test_empty_name_rejected` |
| 18 | 改行含有ファイル名 reject | ar validation | ✅ | エンコーダーで reject |
| 19 | system `ar` 生成アーカイブの decode | system interop | ✅ | `test_ar_decode_system_archive` |
| 20 | 自前 GNU archive → system `ar` で一覧可能 | system interop | ✅ | `test_ar_gnu_system_compat` |
| 21 | 自前 BSD archive → `bsdtar` で一覧可能 | system interop | ✅ | `test_ar_bsd_system_compat` |
| 22 | encoder → decoder roundtrip (GNU/BSD 両方言) | roundtrip | ✅ | `test_roundtrip_gnu_short_name`, `test_roundtrip_gnu_long_name`, `test_roundtrip_bsd_long_name`, `test_ar_roundtrip_gnu` |

### 追加要件

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 23 | BSD symbol table (`__.SYMDEF` / `__.SYMDEF SORTED`) スキップ | [BSD ar](https://man.freebsd.org/cgi/man.cgi?ar(5)) | ✅ | `is_symbol_table()` |
| 24 | ar_date / ar_uid / ar_gid: all-space (空) の許容 | GNU/BSD ar | ✅ | パーサーで space trim |
| 25 | Thin archives (`!<thin>\n`) | GNU ar thin | ✅ | `THIN_MAGIC` 認識、`ArEntry::is_thin` フラグ、`test_thin_archive_decode` |
| 26 | 64-bit GNU symbol table (`/SYM64/`) | GNU ar 64-bit | ✅ | `is_symbol_table()` でスキップ |

---

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 26 |
| **合計** | **26** |
