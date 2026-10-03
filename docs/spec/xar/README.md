# XAR (eXtensible ARchive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | xar プロジェクト wiki の `xarformat` 文書 (mackyle/xar、ローカルスナップショット: `docs/spec/sources/xarformat.wiki`) |
| 参照実装 | 参照 `xar` 1.6.1 ツール (mackyle/xar、BSD-3-Clause、fixture 生成・encode 方向の interop oracle)、`unar` (decode oracle)。詳細: THIRD_PARTY_NOTICES XAR 項 |
| 形式概要 | 3 領域構成: (1) `xar!` magic + header size + version + TOC 長 (圧縮/非圧縮) + checksum アルゴリズムの固定ヘッダ (network byte order)。(2) zlib 圧縮された XML Table of Contents。(3) heap: TOC チェックサム (heap offset 0) + 各ファイルの data run。heap offset は TOC の `<offset>` 値で参照される |
| 実装範囲 | read + write (write は sha1 チェックサム + gzip エンコード固定)。`<ea>` 拡張属性・署名・bzip2/lzma/xz エンコードの data も decode 対応 |

## ヘッダ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | magic は `xar!` (32bit, network order)。不一致は reject | §The Header | ✅ | `bad_magic`, `decode_real` |
| 2 | header size (16bit) は 28 以上。cksum_alg=3 のとき 32 以上かつ 4 の倍数 | 同上 | ✅ | `decode_real` (28), `truncated` |
| 3 | version SHOULD 1。v1 以外は reject (libxar は読み込み時に version を無視するが、本実装は防御的に reject する設計判断) | 同上 ("current version is one" + "ignores the value when reading") | ✅ | `bad_version_rejected` |
| 4 | `toc_length_compressed` / `toc_length_uncompressed` (各 64bit) で TOC 領域を決定 | 同上 | ✅ | `decode_real` |
| 5 | cksum_alg: 0=none, 1=sha1, 2=md5 | 同上 | ✅ | `decode_real` (1), `decode_md5_checksums` (2), `decode_stored_no_checksum` (0) |
| 6 | cksum_alg=3: 拡張ヘッダの NUL 終端 digest 名を読み、"sha1"/"md5" は受理、それ以外は reject。非 4 倍数・28 未満の拡張ヘッダは reject | 同上 | ✅ | cksum_alg 3 分岐実装済み (decode.rs)。合成テストで "sha1" 受理・未知 digest 名 reject を検証。`test_cksum_alg3_named_digest` `test_cksum_alg3_unknown_digest_rejected` |

## Table of Contents (zlib 圧縮 XML)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | TOC はヘッダ直後の zlib 圧縮 XML。`toc_length_compressed` バイトを伸張 | §The Header 末尾注記 | ✅ | `decode_real` |
| 8 | 伸張結果は `toc_length_uncompressed` と一致必須 | 同上 | ✅ | `decode_real` |
| 9 | TOC XML は UTF-8 | §The Table of Contents | ✅ | `decode_real` |
| 10 | XML パーサ: 要素・属性・CDATA・コメント・PI・実体参照 (`&lt;` 等 + `&#NN;`) を受理。閉じタグ不一致・非整形式は reject | 同上 (well-formed XML 前提) | ✅ | `src/archive/xar/xml.rs` + 全 decode テスト経由 |
| 11 | `<checksum style="..."><size>/<offset>` は heap 内の TOC チェックサム位置を示す | 同上 + §The Heap | ✅ | `decode_real` |
| 12 | TOC チェックサムは「圧縮済み TOC バイト列」の digest。heap の `<offset>` 位置と照合 | 同上 ("computed over zlib-compressed toc") | ✅ | `bad_toc_checksum` |
| 13 | cksum_alg と `<checksum style>` の一致を検証 | 同上 (style 名と digest 名の一致要件) | ✅ | `decode_real` 経由 (style 照合実装) |
| 14 | `<file>` 要素は再帰的にネスト可能。directory の `<file>` 子要素は `親名/名前` のパスを構成 | §TOC example (nested `<file>`) | ✅ | `decode_real` (sub/nested.txt) |
| 15 | `<file>` の `<name>` `<type>` は必須 | 同上 | ✅ | `decode_real`; 欠落時 InvalidData |

## Heap / ファイルデータ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | heap offset は TOC 直後からの相対。`<offset>` + `<length>` が格納バイト列、`<size>` が伸張後サイズ | §The Heap | ✅ | `decode_real` |
| 17 | data が heap 範囲外を指す場合は reject | 同上 + crate 防御 | ✅ | 境界チェック実装 (`decode.rs` "data out of heap bounds") |
| 18 | `<encoding style="application/x-gzip"/>` は zlib ストリーム | 同上 + libxar 実測 (78 da) | ✅ | `decode_real` |
| 19 | encoding `none` / `application/octet-stream` は格納データ | 同上 | ✅ | `decode_stored_no_checksum` |
| 20 | `application/x-bzip2`/`application/x-xz`/`application/x-lzma` (LZMA_Alone) はそれぞれ crate codec で伸長、その他未知 encoding は reject | 同上 | ✅ | `decode_bzip2_encoding`, `decode_xz_and_lzma_encodings`, `reject_corrupt_encoded_data` |
| 21 | `<size>` があれば伸張後サイズと一致必須 | 同上 | ✅ | 実装 + `decode_real` 経由 |
| 22 | `<extracted-checksum style="sha1|md5">` は伸張後データの digest。不一致は reject。未知 style は検証しない | 同上 | ✅ | `bad_extracted_checksum`, `decode_md5_checksums` |
| 23 | `<archived-checksum>` は格納バイト列の digest。伸張前に検証、不一致は reject。未知 style は検証しない | 同上 | ✅ | `archived_checksum_catches_tampered_heap`, `archived_checksum_verified_on_valid_archive` |

## エントリモデル / encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 24 | `type=file` はデータ持ち、`type=directory` は is_dir。symlink 等の `<link>` は保持 | §TOC example | ✅ | `decode_real`, `encode_roundtrip` |
| 25 | `<mode>` `<user>` `<group>` `<mtime>` `<atime>` `<ctime>` 等は保持可能なものを entry メタデータとして提供 | 同上 | ✅ | `decode_real` (mode/user/mtime 提供) |
| 26 | encode: `/` 区切りパスをネスト `<file>` 木に変換し、sha1 チェックサム (TOC + extracted + archived) + gzip data で出力 | §TOC + §Heap | ✅ | `encode_roundtrip`, `encode_xml_escape` + oracle interop (実 `xar` 1.6.1 が `-tf`/`-xf` を受理) |
| 27 | XML 特殊文字を含むファイル名は `&amp;`/`&lt;`/`&gt;`/`&quot;` にエスケープ | XML 規則 | ✅ | `encode_xml_escape` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 28 | `xar!` magic で `.xar` を自動検出 | CLI detection | ✅ | `detect_xar` |
| 29 | `archive list`/`read` はパス名 + type/mode/mtime メタデータで一覧化 | CLI semantics | ✅ | `read.rs` の `Format::Xar` アーム |
| 30 | `archive extract` はファイルをパス名で出力 (directory エントリはスキップ) | CLI semantics | ✅ | `extract.rs` の `Format::Xar` アーム |
| 31 | `archive pack xar` は入力をファイル/ディレクトリエントリとして格納 (sha1+gzip 固定) | CLI semantics | ✅ | `write_archive.rs` `pack_xar` + oracle `xar -tf` 受理確認 |
| 32 | fuzz algorithm `xar` | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |

### Intentional scope (実装対象外)

| # | 項目 | 理由 |
|---|------|------|
| 33 | `<ea>` 拡張属性データの抽出 | — | ❌ intentional scope | macOS 固有 (ResourceFork/quarantine 等)。heap 内データの存在は許容するがエントリ化しない |
| 34 | `<signature>` / xar 署名検証 | — | ❌ intentional scope | OpenSSL/CMS 署名で crate スコープ外 |
| 36 | cksum_alg=3 の "sha1"/"md5" 以外の digest 名 | — | ⚠️ | `"sha256"` を `digest()` および archived/extracted-checksum のガードに追加 (`test_cksum_alg3_sha256`, `test_cksum_alg3_sha256_mismatch`)。sha512 など他の OpenSSL ダイジェスト名はハッシュ計算機構を crate 内に持たないため、引き続き `Error::Unsupported` とする |
| 37 | hardlink/character/block special の実データ展開 | — | ❌ intentional scope | TOC メタデータは保持するが特殊ファイル生成は対象外 |
| 38 | heap 内エントリのストリーミング順序要件 (ea を data より先に置き per-file でグループ化する推奨) | — | ❌ intentional scope | 本実装は heap 全体をランダムアクセスで読むため順序制約は不要 |
