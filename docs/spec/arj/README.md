# arj (ARJ archive)

| 項目 | 内容 |
|------|------|
| 基準仕様 | ARJ technical note `TECHNOTE.TXT` (ARJ/UNARJ 配布物同梱、ARJ 2.x file format description)。所在: [Just Solve Wiki: ARJ](http://fileformats.archiveteam.org/wiki/ARJ) (安定した単一ファイル URL なし) |
| 形式概要 | `0x60 0xEA` + `u16le header size` の header ブロック列 (0 = end)。基本 header は 30B 固定 + NUL 終端 filename/comment + u32 header CRC + u16 ext size。main header の後に file header 列と data が続く |
| 実装範囲 | **method 0 (stored) + file type 3 (directory) / 4 (label)** のみ read。write は method-0 のみ。method 1-4 圧縮・garbled (password) エントリは intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 0 (stored) | ARJ technical note | ✅ | ✅ | header/data CRC-32 検証 |
| file_type 3 (dir) / 4 (label) | ARJ technical note | ✅ | — | メタデータエントリ |
| method 1-4 | ARJ technical note | ❌ | ❌ | intentional scope: method 1-3 は仕様不在、4 は二次文書のみ |
| garbled (password) / multi-volume | ARJ technical note | ❌ | ❌ | intentional scope |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | signature `0x60 0xEA` + `u16le hsize`、hsize=0 で終端 | ARJ tech note §header | ✅ | `roundtrip` |
| 2 | 基本 header 30B: first_hdr_size / version / min_ver / host_os / arj_flags / method / file_type / reserved / dos_time u32 / crc32 u32 / packed u32 / orig u32 / name_pos u32 / host_data u16 | ARJ tech note | ✅ | `roundtrip` |
| 3 | filename + comment は NUL 終端文字列 (first_hdr_size の後) | ARJ tech note | ✅ | `read_cstr` |
| 4 | header CRC-32 は hsize バイト本体に対して、header 直後に u32le 格納、不一致は reject | ARJ tech note | ✅ | `rejects_bad_header_crc` |
| 5 | extended header: CRC 直後の u16 size (0 = なし) + data + u32 CRC を skip | ARJ tech note | ✅ | ext サイズ処理 |
| 6 | 先頭 header は main header として読み、entry として返さない | ARJ tech note | ✅ | `roundtrip` |

### メソッド / データ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | method 0 (stored): data は生バイト列、packed == orig 必須 | ARJ tech note | ✅ | `roundtrip` |
| 8 | file_type 3 (directory) / 4 (volume label) は payload なし | ARJ tech note | ✅ | `dir_entry` |
| 9 | method 1-4 (compressed) は `Error::Unsupported` | ARJ tech note | ✅ | `rejects_compressed`, `test_arj_rejects_compressed_method` |
| 10 | arj_flags bit0 (garbled/password) は `Error::Unsupported` | ARJ tech note | ✅ | decode 内検査 |
| 11 | entry data CRC-32 を検証、不一致は reject | ARJ tech note | ✅ | decode 内検証 |
| 12 | bounds 検査 (truncated signature/header/data → エラー) | crate エラー規約 | ✅ | `test_arj_rejects_truncated` |
| 13 | filename は UTF-8 必須 | crate エラー規約 | ✅ | `read_cstr` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 14 | `ArjEncoder`: main header (host_os=unix) を先頭に出力し、method-0 file header + data、dir は file_type 3 | ARJ tech note | ✅ | `roundtrip`, `dir_entry` |
| 15 | 終端 `0x60 0xEA` + `u16` 0 を付与、各 header に ext size 0 を付与 | ARJ tech note | ✅ | 往復テスト |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 16 | crate 生成 method-0 `.arj` を `7z` が list/extract | system interop | ✅ | `test_arj_7z_list_interop` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | `0x60 0xEA` signature で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_arj` (同上: spawn 統合テスト基盤は未整備) |
| 18 | fuzz harness `arj` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Arj` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | method 1-4 圧縮データの decode は非対応 | ❌ | `Error::Unsupported` を返す |
| 20 | garbled (password protected) アーカイブは非対応 | ❌ | flag bit0 で `Error::Unsupported` |
| 21 | multi-volume (flag bit2) / security envelope / chapter 機能は非対応 | ❌ | volume 分割は扱わない |
| 22 | write は method-0 のみ | ❌ | 圧縮エンコーダは非対応 |

### 実装メモ

- `first_hdr_size` が基本ヘッダ (30B) を超える場合、超過分は拡張ヘッダとして読み飛ばす (内容は解釈しない)。
- ファイルコメントのクレームテストは行っていない (ヘッダ直後の NUL 区切り文字列として受理のみ)。
