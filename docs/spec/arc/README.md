# arc (SEA ARC)

| 項目 | 内容 |
|------|------|
| 基準仕様 | ARC file format description (System Enhancement Associates / wotsit "arc" entry、[fileformat.info mirror](https://www.fileformat.info/format/arc/corion.htm)、ローカルスナップショット: `docs/spec/sources/arc_format_corion.htm`) |
| 形式概要 | 各 member は `0x1A` + method byte で開始、method 0 で終端。name は 13B NUL 埋めの flat 名 (directory 概念なし) |
| 実装範囲 | **method 1 (obsolete unpacked) / method 2 (stored)** のみ read。write は method-2 のみ。method 3 (packed/RLE)・4 (squeezed)・5-8 (crunched/crushed/distilled) 以降は intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 1 (obsolete unpacked) | ARC spec | ✅ | ✅ | CRC-16 フィールドなし |
| method 2 (stored) | ARC spec | ✅ | ✅ | CRC-16 検証 |
| method 3-9 (packed/squeezed/crunched/crushed/distilled/squashed) | ARC spec | ❌ | ❌ | intentional scope: 圧縮内部仕様の書面文書なし |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | member marker `0x1A` + method byte、method 0 で終端 | ARC spec | ✅ | `roundtrip` |
| 2 | filename: 13 バイト NUL 埋め。`/`・`\` を含む場合は reject | ARC spec | ✅ | `parse_name` |
| 3 | method 1: `[name][size u32le][data]` — date/time/CRC/length フィールドなし | ARC spec | ✅ | `method1_member`, `test_arc_method1_member` |
| 4 | method 2: `[name][size u32le][date u16][time u16][crc16 u16][length u32le][data]` | ARC spec | ✅ | `roundtrip` |
| 5 | bounds 検査 (truncated header/marker/data → エラー) | crate エラー規約 | ✅ | `test_arc_rejects_truncated` |
| 6 | filename は UTF-8 必須 | crate エラー規約 | ✅ | `parse_name` |

### メソッド / データ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | method 1/2: data は生バイト列、stored size == member size 必須 | ARC spec | ✅ | `roundtrip`, `method1_member` |
| 8 | method 3 (packed)・4 (squeezed)・5-8 以降は `Error::Unsupported` | ARC spec | ✅ | `rejects_compressed_method`, `test_arc_rejects_compressed_method` |
| 9 | method 2 の CRC-16 (CRC-16/ARC、poly 0x8005 reflected) を検証、不一致は reject | ARC spec | ✅ | `rejects_bad_crc` |
| 10 | method 1 member は CRC フィールドを持たないため `crc16: None` で返す | ARC spec | ✅ | `method1_member` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 11 | `ArcEncoder::add_file` / `encode`: method-2 member + name 1-12B・NUL/パス区切りなし | ARC spec | ✅ | `roundtrip`, `rejects_long_name` |
| 12 | 終端 `0x1A 0x00` を付与 | ARC spec | ✅ | 往復テスト |
| 16 | method-1 member の emit: `add_file_with_method(name, data, date, time, 1)` — `[0x1A][1][name 13B][size u32le][data]` (CRC/date/time/length なし) | ARC spec | ✅ | `method1_roundtrip`, `method1_header_layout`, `rejects_unsupported_encode_method`, `test_arc_method1_encode_decode_roundtrip`, `test_arc_method1_header_layout`, `test_arc_rejects_unsupported_encode_method` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | `0x1A` + method byte (1-8) で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_arc` (同上: spawn 統合テスト基盤は未整備) |
| 14 | fuzz harness `arc` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Arc` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 15 | method 3-8+ (packed/squeezed/crunched/crushed/distilled/squashed) の decode は非対応 | ❌ | `Error::Unsupported` を返す |
| 17 | 外部ツールとの相互運用検証なし | ❌ | コンテナに ARC 対応ツール (unar 等) がないため、自己往復 + 手組みベクタのみ |
