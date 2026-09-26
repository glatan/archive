# mtree (BSD mtree manifest)

| 項目 | 内容 |
|------|------|
| 基準仕様 | FreeBSD `mtree(5)` man page + libarchive `archive_read_support_format_mtree` 挙動 |
| 形式概要 | 行指向テキスト。`#`コメント/`#mtree` signature、`/set`・`/unset`、相対・full path エントリ、`..` でディレクトリ遡上 |
| 実装範囲 | **read のみ**。ファイル内容を持たないマニフェスト形式のため `ArchiveEntry::data` は常に空 |

参照: `mtree(5)` (FreeBSD), <https://man.freebsd.org/cgi/man.cgi?mtree(5)>

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
| 10 | UTF-8 以外の入力は reject | crate エラー規約 | ✅ | `rejects_non_utf8` |

### キーワード

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | `type=` : file/dir/link/block/char/fifo/socket を `MtreeKind` に写像、未知値は `Other` | Keywords/type | ✅ | `kind_of` |
| 12 | `size` `mode`(8進) `uid` `gid` `uname` `gname` `time` `link` を構造化フィールドで公開 | Keywords | ✅ | `parses_basic_manifest` |
| 13 | digest 系 (`md5`/`sha1`/`sha256`/`sha384`/`sha512`/`rmd160` + `*digest` 別名) を正規化名で `digests` に格納 | Keywords (digest synonyms) | ✅ | `digest_synonyms_normalised` |
| 14 | 未知キーワードは値を保持せず無視 (warn 相当: パース継続) | Keywords ("warn about unrecognized") | ✅ | `entry_from` (無視) |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | `bsdtar -cf out.mtree --format=mtree` 生成マニフェストを decode、エントリ名と size を照合 | system interop | ✅ | `test_mtree_bsdtar_interop` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | `#mtree` 先頭で `.mtree` を自動検出 | CLI detection | ✅ | `detect_mtree` |
| 17 | `archive read` は entry をメタデータ付きで一覧化 (payload なし) | CLI semantics | ✅ | `read.rs` の `Format::Mtree` アーム |
| 18 | `archive extract` は Unsupported を返す (内容を持たない) | CLI semantics | ✅ | `extract.rs` の `Format::Mtree` アーム |
| 19 | fuzz algorithm `mtree` | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 20 | write / encode | — | ❌ | read-only parser として設計 |
| 21 | `contents=`/`ignore`/`nochange`/`flags`/`cksum`/`nlink` のセマンティクス適用 | Keywords | ❌ | キーワードは受理するが属性検証ツールとしての意味解釈は対象外 |
| 22 | digest の実ファイル照合 | Keywords | ❌ | mtree はファイルシステム監査用であり、本ライブラリは manifest の構造パースのみ |
