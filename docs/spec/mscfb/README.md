# MS-CFB (Compound File Binary)

| 項目 | 内容 |
|------|------|
| 形式概要 | 512/4096 バイトセクター + FAT/DIFAT/mini FAT/ディレクトリエントリによるファイル内ファイルシステム。旧 Office (.doc/.xls/.ppt)、MSI、OLE2 構造化ストレージのコンテナ |
| 基準仕様 | [[MS-CFB] v20210625](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b) (スナップショット: `docs/spec/sources/MS-CFB.pdf`) |
| 実装 | `archive::archive::mscfb::decode` (read のみ)。`mscfb` feature 配下 |

## ヘッダ・セクター層

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | signature `D0 CF 11 E0 A1 B1 1A E1` 検証 | [MS-CFB] §2.2 | ✅ | `rejects_bad_signature_and_truncation` |
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
| 11 | Name は UTF-16LE、長 ≤64B、偶数、終端 NUL 必須、サロゲート不正は拒否 | §2.6.1 | ✅ | `rejects_unterminated_name` |
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

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | compound file write | ❌ intentional scope | red-black 木の構築・FAT 確保・トランザクションは別仕事。read が本フォーマットの主用途。write 参照実装は manifest `no_url_available` の `mscfb-write-refs` (cfb crate / Apache POI / libgsf) |
| 20 | Range Lock sector (offset 0x7FFFFFFF) / トランザクション signature | ❌ intentional scope | 並行アクセス制御はコンテナ展開に不要。signature は読み飛ばし |
| 22 | 大文字 mapping / red-black 挿入順序 | ⚠️ 列挙は DFS で網羅、名前順序保証なし | 検索用ソート規則は write 時にのみ意味を持つ |
| 23 | version 3 で上位 32bit が非ゼロな stream size の寛容読み | ❌ intentional scope | spec は「parser は上位を無視すべき」と推奨。本実装は規格上限超過を厳格拒否 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み | 19 |
| ⚠️ 部分対応 | 1 |
| ❌ 未対応 | 3 |
| **合計** | **23** |
