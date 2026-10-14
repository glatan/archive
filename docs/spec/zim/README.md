# zim (ZIM archive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | openZIM Wiki "[ZIM file format](https://wiki.openzim.org/wiki/ZIM_file_format)" (ローカルスナップショット: `docs/spec/sources/zim_file_format.html`) |
| 参照実装 | なし (書面仕様のみに基づいて実装。openzim zim-testing-suite の `small.zim` で手動デコード検証を行っているが、外部 ZIM ツールによる oracle 利用はない) |
| 形式概要 | 80B header + MIME list + path/title pointer list + dirent + cluster pointer list + blob cluster |
| 実装範囲 | read/write (write は v5/v6、compression none/xz/zstd、redirect/deprecated entry も emit 可)。fulltext index 検索 API は intentional scope 外 |

参照: <https://wiki.openzim.org/wiki/ZIM_file_format>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| format v5 / v6 | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | ✅ | v5/v6 とも write 可。extended cluster (bit5 + 8B offset table)・redirect (0xffff)・deprecated (0xfffe/0xfffd) dirent の emit に対応 (`ZimEncoder::with_version`/`with_extended_cluster`/`add_redirect`/`add_deprecated`) |
| compression none (1) / xz-lzma2 (4) / zstd (5) | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | ✅ | encode は `ZimEncoder::with_compression` |
| compression zlib (2) / bzip2 (3) | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | — | legacy id。`zlib` / `bzip2` feature 有効時に decode (無効時は `Unsupported`) |
| extended cluster (8B offset) | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | ✅ | cluster info bit5。encode は `with_extended_cluster` (v6 のみ) |

### Header / エントリ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | magic `0x044D495A` (LE u32)、major 5/6 のみ受理 | Header | ✅ | `parses_basic_zim` / `rejects_unsupported_version` |
| 2 | entryCount / clusterCount / pathPtrPos / titlePtrPos / clusterPtrPos / mimeListPos / checksumPos を解釈 | Header | ✅ | `ZimBuilder` フィクスチャ。uuid (16B) は decode 無視・encode ゼロ埋め、mainPage/layoutPage は decode 未消費・encode `0xffffffff` 固定 |
| 3 | path pointer list: entryCount × u64 offset → dirent | Path Pointer List | ✅ | `parse_dirent` |
| 4 | Content entry: mimetype(2) + param_len(1) + namespace(1) + revision(4) + cluster(4) + blob(4) + path + title | Directory Entries | ✅ | `parses_basic_zim` |
| 5 | Redirect entry (mimetype=0xffff): redirect_index 経由で target entry の content を解決 (多段リダイレクトは対象外、1 段のみ解決) | Directory Entries | ✅ | `resolves_redirect` |
| 6 | deprecated entry (0xfffe linktarget / 0xfffd deleted) は skip | Directory Entries | ✅ | `skips_deprecated_linktarget_and_deleted_entries` |
| 7 | エントリ名は `N/path` 形式 (namespace prefix + path) で公開 | Namespaces | ✅ | `C/index.html` 等 |

### Cluster

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 8 | cluster info byte: 下位 4bit = compression (1:none / 2:zlib / 3:bzip2 / 4:xz(lzma2) / 5:zstd)、bit5 = extended offset | Clusters | ✅ | `parses_xz_cluster` / `test_zim_decode_zstd_cluster` / `parses_zlib_cluster` / `parses_bzip2_cluster` |
| 9 | extended (8B offset) cluster は major 6 のみ受理 | Clusters | ✅ | `rejects_extended_cluster_below_major6`, `parses_extended_cluster_major6` |
| 10 | blob offset list: 先頭 offset / OFFSET_SIZE で entry 数を決定、連続 offset 差分が blob | Clusters | ✅ | `parses_multi_blob_cluster`。先頭 offset の OFFSET_SIZE アライメントも検査。cluster 終端は次クラスタ位置→checksumPos→input 末尾の順でフォールバック |
| 11 | legacy compression id (2 zlib / 3 bzip2): `zlib`/`bzip2` feature 有効時は decode、無効時は `Unsupported` | Clusters | ✅ | `parses_zlib_cluster`, `parses_bzip2_cluster`, `rejects_zlib_cluster`, `rejects_bzip_cluster` (feature 無効経路) |
| 12 | bounds 検査 (pointer list / blob offset / truncation) | crate エラー規約 | ✅ | `rejects_truncated`, `rejects_blob_out_of_range` |

### 実ファイル検証

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | openzim zim-testing-suite `small.zim` (v5.0, 17 entries, xz + stored cluster) の decode を手動検証済み | real-world interop | ✅ | ローカル検証 (fixture 非添付) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 14 | magic `0x044D495A` で `.zim` を自動検出 | CLI detection | ✅ | `detect_zim` |
| 15 | `archive extract` は entry を展開 | CLI semantics | ✅ | `extract.rs` の `Format::Zim` アーム |
| 16 | fuzz algorithm `zim` (stored fixture + decode) | fuzz harness | ✅ | `fuzz/src/algorithms.rs` |
| 17 | encode: 80B header + MIME list + dirent + path/title pointer list + cluster pointer + blob cluster の v5 レイアウトを出力 | Header, Directory Entries, Clusters | ✅ | `stored_roundtrip`, `test_zim_encoder_roundtrip` |
| 18 | encode: cluster compression none (1) / xz (4) / zstd (5) を選択可能。offset table + blob 列を単一 stream で圧縮 | Clusters | ✅ | `xz_and_zstd_roundtrip`, `test_zim_encoder_xz_stored` |
| 19 | encode: 末尾 16B MD5 archive checksum を実値出力 | Header checksumPos | ✅ | `emits_md5_checksum` |
| 20 | encode: path pointer list は path ソート順、title pointer list は title (=path) ソートの u32 dirent index 列 | Path/Title Pointer List | ✅ | `stored_roundtrip` (decode が pathPtr 経由で解決) |
| 21 | archive MD5 checksum 検証 | Header checksumPos | ✅ | `verifies_archive_md5`・`rejects_bad_archive_md5`・`rejects_tampered_content_via_md5` (末尾 digest 存在時のみ検証、欠落は許容)、`truncated_prefix_invariant` (任意の切断位置でエラーまたは正当なエントリ接頭辞)。write は実値出力済み (行 19) |
| 21a | split archive (.zimaa/.zimab...) の decode | Split ZIM archives | ✅ | `decode_parts(&[&[u8]])` が part を連結して decode (分割可能位置は cluster 境界のみだが reader は任意境界でも受理)。`split_parts_roundtrip`, `split_parts_rejects_empty` |
| 21b | title pointer list 順の entry 列 API | Title Pointer List | ✅ | `decode_title_order` が titlePtrPos の u32 index 列でソート (欠落/不正なら path 順)。`title_order_uses_title_pointer_list`, `title_order_falls_back_on_invalid_list` |
| 21c | MIME type メタデータと title の公開 | MIME Type List, Directory Entries | ✅ | `ZimEntry::mime_type` (MIME list 参照、redirect は空) / `ZimEntry::title` (空 title は bare path にフォールバック、未終端の切り詰め title は空として扱う許容動作)。`exposes_mime_type_and_title`, `resolves_redirect` |
| 21d | cluster compression id 0 (素データの別表現として一部の writer が使用) は受理せず `Unsupported` | Clusters | ✅ | `rejects_unknown_cluster_compression` (id 0 は `CLUSTER_NONE`(1) のみ受理経路外 → `_` arm で reject) |
| 25 | v6 write / extended cluster の出力、redirect・deprecated entry の出力 | Directory Entries, Clusters | ✅ | `ZimVersion::{V5,V6}` + `with_extended_cluster` + `add_redirect` + `add_deprecated`。`v6_extended_cluster_roundtrip`, `v6_plain_cluster_roundtrip`, `extended_cluster_requires_v6`, `redirect_roundtrip`, `redirect_missing_target_rejected`, `redirect_to_non_content_rejected`, `deprecated_entries_skipped_on_decode`, `v6_extended_with_redirect_and_deprecated`, `test_zim_encoder_v6_extended_with_redirect` |
| 26 | `X/listing/titleordered/v0` title index | Title Pointer List (titlePtrPos は obsolete 注記あり) | ✅ | `decode_title_order` は `titlePtrPos` より `v0` リスティングを優先して参照し、形式不正時は `titlePtrPos` にフォールバックする (`title_order_uses_x_listing_v0`, `title_order_prefers_listing_over_titleptrpos`, `title_order_falls_back_when_listing_malformed`) |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 22 | fulltext index 検索 API | openzim wiki (format doc 外) | ❌ | title pointer list 順の列挙は `decode_title_order` で提供 (21b)。fulltext index そのものの検索は対象外 |
| 21e | dirent path の `.` / `..` セグメント・絶対パス禁止 | Directory Entries | ❌ intentional scope | decoder は path を `N/path` としてそのまま公開し、dot セグメント検証を行わない。zip/tar 等と同じく decoder は生名を公開し抽出側でサニタイズする crate ポリシー (`archive-cli` の `sanitize_relative_path` が `..` を reject) |
