# zim (ZIM archive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | openZIM Wiki "[ZIM file format](https://wiki.openzim.org/wiki/ZIM_file_format)" (ローカルスナップショット: `docs/spec/sources/zim_file_format.html`) |
| 形式概要 | 80B header + MIME list + path/title pointer list + dirent + cluster pointer list + blob cluster |
| 実装範囲 | **read のみ** (write / MIME メタデータ / title index / archive checksum 検証は intentional scope 外) |

参照: <https://wiki.openzim.org/wiki/ZIM_file_format>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| format v5 / v6 | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | ❌ | write は intentional scope 外 |
| compression none (1) / xz-lzma2 (4) / zstd (5) | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | — | |
| compression zlib (2) / bzip2 (3) | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ❌ | — | legacy id → `Unsupported` |
| extended cluster (8B offset) | [ZIM file format wiki](https://wiki.openzim.org/wiki/ZIM_file_format) | ✅ | — | cluster info bit5 |

### Header / エントリ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | magic `0x044D495A` (LE u32)、major 5/6 のみ受理 | Header | ✅ | `parses_basic_zim` / `rejects_unsupported_version` |
| 2 | entryCount / clusterCount / pathPtrPos / titlePtrPos / clusterPtrPos / mimeListPos / checksumPos を解釈 | Header | ✅ | `ZimBuilder` フィクスチャ |
| 3 | path pointer list: entryCount × u64 offset → dirent | Path Pointer List | ✅ | `parse_dirent` |
| 4 | Content entry: mimetype(2) + param_len(1) + namespace(1) + revision(4) + cluster(4) + blob(4) + path + title | Directory Entries | ✅ | `parses_basic_zim` |
| 5 | Redirect entry (mimetype=0xffff): redirect_index 経由で target entry の content を解決 (多段リダイレクトは対象外、1 段のみ解決) | Directory Entries | ✅ | `resolves_redirect` |
| 6 | deprecated entry (0xfffe linktarget / 0xfffd deleted) は skip | Directory Entries | ✅ | `skips_deprecated_linktarget_and_deleted_entries` |
| 7 | エントリ名は `N/path` 形式 (namespace prefix + path) で公開 | Namespaces | ✅ | `C/index.html` 等 |

### Cluster

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 8 | cluster info byte: 下位 4bit = compression (1:none / 4:xz(lzma2) / 5:zstd)、bit5 = extended offset | Clusters | ✅ | `parses_xz_cluster` / `test_zim_decode_zstd_cluster` |
| 9 | extended (8B offset) cluster は major 6 のみ受理 | Clusters | ✅ | `rejects_extended_cluster_below_major6`, `parses_extended_cluster_major6` |
| 10 | blob offset list: 先頭 offset / OFFSET_SIZE で entry 数を決定、連続 offset 差分が blob | Clusters | ✅ | `parses_multi_blob_cluster`。先頭 offset の OFFSET_SIZE アライメントも検査。cluster 終端は次クラスタ位置→checksumPos→input 末尾の順でフォールバック |
| 11 | legacy compression id (2 zlib / 3 bzip2) → Unsupported | Clusters | ✅ | `rejects_bzip_cluster`, `rejects_zlib_cluster` |
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

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 17 | write / encode | crate-local | ❌ | read-only reader として設計 |
| 18 | archive MD5 checksum 検証 | Header checksumPos | ❌ | パースのみ (検証は行わない) |
| 19 | title pointer list / fulltext index の検索 API | Title Pointer List | ❌ | archive listing/extract には path index のみ使用 |
| 20 | MIME type メタデータの公開 | MIME Type List | ❌ | コンテンツ種別は `ArchiveEntry` に含めない |
| 21 | split archive (.zimaa/.zimab...) | Split ZIM archives | ❌ | 単一ファイルのみ |
