# MS-CFB (Compound File Binary)

| 項目 | 内容 |
|------|------|
| 形式概要 | 512/4096 バイトセクター + FAT/DIFAT/mini FAT/ディレクトリエントリによるファイル内ファイルシステム。旧 Office (.doc/.xls/.ppt)、MSI、OLE2 構造化ストレージのコンテナ |
| 基準仕様 | [[MS-CFB] v20210625](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b) (スナップショット: `docs/spec/sources/MS-CFB.pdf`) |
| 参照実装 | 独自 Python 参照ジェネレータ ([MS-CFB] §2 準拠、テスト時 oracle) + `olefile` (BSD-style、encoder 出力の parse oracle)。write 側参照実装 (cfb crate MIT / Apache POI Apache-2.0 / libgsf LGPL-2.1) は manifest `mscfb-write-refs` 参照。詳細: THIRD_PARTY_NOTICES mscfb 項 |
| 実装 | `archive::archive::mscfb::{decode, decode_strict, encode::CfbEncoder}` (read/write)。`mscfb` feature 配下 |

## ヘッダ・セクター層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | signature `D0 CF 11 E0 A1 B1 1A E1` 検証 | [MS-CFB] §2.2 | ✅ | `rejects_bad_signature_and_truncation`、`truncated_at_every_position` (全切断位置で拒否) |
| 2 | Major Version 3 (512B) / 4 (4096B) のみ受理、Byte Order `0xFFFE`、Sector Shift 0x09/0x0C、Mini Sector Shift 0x06 検証 | §2.2 | ✅ | roundtrip + reject 系 |
| 3 | Mini Stream Cutoff `0x1000` 検証 | §2.2 | ✅ | decode 時 assert |
| 4 | v3 は Number of Directory Sectors == 0 必須 | §2.2 | ✅ | decode 時 assert |
| 5 | セクター番号 → オフセット `(n+1) * sector_size`、MAXREGSECT 超の値は拒否 | §2.1/§2.3 | ✅ | chain 系全般 |
| 6 | DIFAT: ヘッダ内 109 エントリ + DIFAT セクターチェーン (最後の 4B が next リンク)、FREESECT を skip、count は Number of FAT Sectors が正本 | §2.5 | ✅ | 単一 FAT セクターでカバー; chain は reject 経路で到達 |
| 7 | FAT チェーン walk: ENDOFCHAIN 終端、FREESECT/循環/out-of-range を拒否 | §2.3 | ✅ | `rejects_chain_cycle`、integration truncation テスト |

## ディレクトリ層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 8 | ディレクトリ = FAT チェーン上の 128B エントリ配列 | §2.6 | ✅ | 全テスト |
| 9 | entry #0 は Root Storage Object (type 0x05) 必須 | §2.6.2 | ✅ | decode 時 assert |
| 10 | Object Type ∈ {0,1,2,5} 検証 (3/4 は不正) | §2.6.1 | ✅ | decode 時 assert |
| 11 | Name は UTF-16LE、長 ≤64B、偶数、終端 NUL 必須、サロゲート不正は拒否。未割当エントリ (Object Type 0x00) の name フィールドは未定義のため検証・デコード対象外 | §2.6.1 / §2.6.3 | ✅ | `rejects_unterminated_name`, `test_fuzz_regression_mscfb_v4_corrupt` |
| 12 | 列挙: root.child から red-black 木を left/node/right DFS。storage は path 成分、stream のみ entry 出力 (`Storage/Sub/Name`) | §2.6.4 | ✅ | `storage_children_get_path_prefix`、`sibling_chain_enumerates_all` |
| 13 | stream ID 循環・範囲外を拒否 | §2.6.1 | ✅ | `visited` セット + depth 制限 |
| 14 | v3 の stream size ≤ 0x80000000 (上位 32bit が非ゼロの旧実装ファイルはサイズ解釈を 32bit に限定せず規格値として扱い超過なら拒否) | §2.6.1 | ✅ | decode 時 assert |
| 21 | CLSID / State Bits / FILETIME の公開 | §2.6.1 | ✅ | stream entry は `CfbEntry.meta` (`CfbEntryMeta`: clsid/state_bits/created/modified、FILETIME は生 u64)、root storage は `root_meta()` で公開。`exposes_stream_entry_metadata`, `root_meta_reads_root_entry` |

## mini stream 層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | size < cutoff の stream は mini stream (root entry の FAT チェーン) 内 64B ミニセクターを mini FAT で chain | §2.4/§2.6.2 | ✅ | `decodes_mini_stream` |
| 16 | mini FAT 自身は Number of Mini FAT Sectors 個の通常セクターチェーン | §2.4 | ✅ | `decodes_mini_stream` |
| 17 | size ≥ cutoff の stream は通常 FAT チェーン | §2.7 | ✅ | `decodes_regular_sector_stream` (5000B/10 セクター) |
| 18 | チェーン終端到達前に size 分読めない/超過読みをした場合の切り詰め拒否 | §4.1 | ✅ | `rejects_bad_signature_and_truncation` |
| 19 | compound file write | [MS-CFB] | ✅ | `CfbEncoder` で v3/v4 image 生成 (FAT/miniFAT チェーン、4096B mini stream cutoff、名前ソート balanced binary tree directory、DIFAT)。`roundtrip_stream_tree`, `mini_stream_roundtrip`, `v4_sector_roundtrip`, `difat_chain_roundtrip`, `empty_file_roundtrip`。CLSID/state bits/timestamp は emit しない (writer 側 scope 外)。write 参照実装は manifest `no_url_available` の `mscfb-write-refs` (cfb crate / Apache POI / libgsf)。fuzz harness `mscfb`/`mscfb-v4` で roundtrip + corrupt 対象 |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 20 | Range Lock sector (offset 0x7FFFFFFF) / トランザクション signature | ❌ intentional scope | 並行アクセス制御はコンテナ展開に不要。signature は読み飛ばし |
| 22 | 大文字 mapping / red-black 挿入順序 | ✅ | `decode::get_stream(input, path)` が各 storage の sibling red-black 木を §2.6.4 ソート規則 (大文字化 UTF-16 code unit、長さ→code unit 順、`mod.rs` の `sort_key`/`key_cmp` で encode と共通化) で二分下降して lookup。`decode::decode_sorted` は §2.6.4 規則の順序列挙 (非整列木でも順序保証)。`get_stream_resolves_sibling_tree`, `get_stream_misses_unknown_and_non_stream_paths`, `decode_sorted_orders_by_264_sort_rule`, `decode_sorted_fixes_unsorted_tree` |
| 24 | red-black color ビット (byte 67) の検証・sibling/child ID の NOSTREAM 規約・同一 storage 内の名前重複なし要件 | ✅ opt-in | `decode_strict` で color バイト、NOSTREAM 規約、および同一 storage 内の重複名を検証する (`rejects_invalid_color_byte`, `rejects_stream_with_child`, `rejects_duplicate_sibling_names`)。既定の `decode` が寛容な処理 (lenient) を維持するのは後方互換のための設計判断 |
| 23 | version 3 で上位 32bit が非ゼロな stream size の寛容読み | ❌ intentional scope | [MS-CFB] §2.6.1 は「parser は上位 32bit を無視すべき」と推奨。本実装は上位 32bit が非ゼロ (解釈サイズ > `u32::MAX`) の場合のみ `stream_data` で `InvalidData` を返し、上位が 0 で 2-4 GiB の場合は受理する |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 22 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 2 (intentional scope) |
| **合計** | **24** |
