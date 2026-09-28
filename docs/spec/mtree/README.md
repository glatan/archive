# mtree (BSD mtree manifest)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [mtree(5) man page](https://man.freebsd.org/cgi/man.cgi?mtree(5)) (FreeBSD、ローカルスナップショット: `docs/spec/sources/mtree_5_freebsd.html`) + libarchive [`archive_read_support_format_mtree.c`](https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_format_mtree.c) 挙動 |
| 形式概要 | 行指向テキスト。`#`コメント/`#mtree` signature、`/set`・`/unset`、相対・full path エントリ、`..` でディレクトリ遡上 |
| 実装範囲 | read/write 両対応。ファイル内容を持たないマニフェスト形式のため `ArchiveEntry::data` は常に空 |

参照: `mtree(5)` (FreeBSD), <https://man.freebsd.org/cgi/man.cgi?mtree(5)>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| FreeBSD mtree(5) | [mtree(5) man page](https://man.freebsd.org/cgi/man.cgi?mtree(5)) | ✅ | ✅ | write は full-path 形式のみ |
| libarchive mtree 方言 | [`archive_read_support_format_mtree`](https://github.com/libarchive/libarchive/blob/master/libarchive/archive_read_support_format_mtree.c) 挙動 | ✅ | ✅ | `/set`・`/unset`・8進エスケープ・`<alg>digest=` 出力、bsdtar が入力として受理 |

### 行フォーマット

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | `#` 開始行はコメント (`#mtree` signature を含む) | Comment | ✅ | `comments_and_blank_lines_skipped` |
| 2 | `#mtree` signature は任意 (必須としない) | BUGS 節 ("not yet widely implemented") | ✅ | `no_signature_required` |
| 3 | `/set key=val...` は後続エントリの既定値を設定 | Special commands | ✅ | `unset_removes_defaults` |
| 4 | `/unset key...` は既定値を解除 | Special commands | ✅ | `unset_removes_defaults` |
| 5 | 最初のトークンに `/` を含まなければ現在ディレクトリ内の相対名 | Relative | ✅ | `relative_entries_descend_into_dirs` |
| 6 | 最初のトークンが先頭文字以降に `/` を含めば full path (開始ディレクトリ基準) | Full | ✅ | `full_paths_are_absolute_relative_to_root` |
| 7 | 相対エントリで `type=dir` なら現在ディレクトリを push | Relative | ✅ | `relative_entries_descend_into_dirs` |
| 8 | `..` は現在ディレクトリを pop、keyword は無視 | dot-dot | ✅ | `relative_entries_descend_into_dirs` |
| 9 | `\ooo` 8進エスケープと `\\` を名前・値で decode | libarchive mtree escaping | ✅ | `octal_escapes_in_names` |
| 10 | UTF-8 以外の入力は reject、空パス行は `InvalidData` | crate エラー規約 | ✅ | `rejects_non_utf8` |

### キーワード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | `type=` : file/dir/link/block/char/fifo/socket を `MtreeKind` に写像、未知値は `Other` | Keywords/type | ✅ | `kind_of` |
| 12 | `size` `mode`(8進) `uid` `gid` `uname` `gname` `time` `link` を構造化フィールドで公開 | Keywords | ✅ | `parses_basic_manifest` |
| 13 | digest 系 (`md5`/`sha1`/`sha256`/`sha384`/`sha512`/`rmd160` + `*digest` 別名) を正規化名で `digests` に格納 | Keywords (digest synonyms) | ✅ | `digest_synonyms_normalised` |
| 14 | 未知キーワードは値を保持せず無視 (warn 相当: パース継続) | Keywords ("warn about unrecognized") | ✅ | `unknown_keyword_ignored` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | `#mtree` signature + full-path エントリ行 (`./a/b/c.txt` + `key=value`) を emit | mtree(5) Full entries | ✅ | `roundtrip_basic` |
| 16 | `/set`・`/unset`・`#` コメント行を emit、既定値は decode 側に適用される | Special commands | ✅ | `set_unset_defaults_roundtrip` |
| 17 | 名前・値は空白・`#`・`\\`・制御・非 ASCII を `\ooo` 8進エスケープ (decode の unescape と対称) | libarchive mtree escaping | ✅ | `escapes_space_and_special` |
| 18 | `type=` は全 `MtreeKind` (`Other` 含む) を逆写像、digest は `<alg>digest=` 形式 (libarchive 互換) | Keywords | ✅ | `roundtrip_all_kinds`, `roundtrip_basic` |
| 19 | 空・`..` 要素を含むパスは reject、空白/`=`/`#` を含むキーワード名・CR/LF 混入は reject | crate エラー規約 | ✅ | `rejects_bad_input` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 20 | `bsdtar -cf out.mtree --format=mtree` 生成マニフェストを decode、エントリ名と size を照合 | system interop | ✅ | `test_mtree_bsdtar_interop` |
| 21 | crate 生成マニフェストを `bsdtar -tf` が入力として読みエントリ名列挙 | system interop | ✅ | `test_mtree_bsdtar_read_interop` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | `#mtree` 先頭で `.mtree` を自動検出 (signature 非保持の mtree は CLI 検出対象外。decoder 自体は signature なしでも受理) | CLI detection | ✅ | `detect_mtree` |
| 23 | `archive read` は entry をメタデータ付きで一覧化 (payload なし) | CLI semantics | ✅ | `read.rs` の `Format::Mtree` アーム |
| 24 | `archive extract` は Unsupported を返す (内容を持たない) | CLI semantics | ✅ | `extract.rs` の `Format::Mtree` アーム |
| 25 | fuzz algorithm `mtree` | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 26 | `contents=`/`ignore`/`nochange`/`flags`/`cksum`/`nlink` のセマンティクス適用 (decode/encode とも構造のみ) | Keywords | ❌ | キーワードは受理するが属性検証ツールとしての意味解釈は対象外 |
| 27 | digest の実ファイル照合 (decode 側) | Keywords | ❌ | mtree はファイルシステム監査用であり、本ライブラリは manifest の構造処理のみ |
