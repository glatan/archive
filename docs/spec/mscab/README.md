# mscab (Microsoft Cabinet)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [[MS-CAB]](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) Cabinet File Format (Microsoft Open Specifications、2011-03-04 版 PDF。HTML 版: <https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10)>、ローカルスナップショット: `docs/spec/sources/ms-cab_20110304.pdf`) |
| 形式概要 | CFHEADER + CFFOLDER 配列 + CFFILE 配列 + CFDATA ブロック列。フォルダ単位で圧縮 |
| 実装範囲 | read/write (単一 cabinet・単一 folder の NONE/MSZIP)。Quantum / LZX / multi-cabinet set は intentional scope 外 |

参照: <https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| compression NONE | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) | ✅ | ✅ | 単一 folder write |
| compression MSZIP | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) + [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951.txt) | ✅ | — | `compress::deflate` 再利用 |
| compression Quantum / LZX | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) | ❌ | — | intentional scope (1997 文書版 LZX の誤記・Quantum 仕様不在) |
| multi-cabinet set | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) | ❌ | — | 単一キャビネットのみ |

### ヘッダ / エントリ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | CFHEADER: magic `MSCF`、reserved フィールド、cbCabinet、coffFiles、cFolders、cFiles、flags (全て LE)。setID / iCabinet は単一 cabinet reader では読み飛ばし | MS-CAB §2.1 | ✅ | `parses_stored_cabinet` |
| 2 | version 1.x (major=1, minor<=3) を受理、それ以外は reject | MS-CAB §2.1 | ✅ | `rejects_bad_major_version`, `rejects_bad_minor_version` |
| 3 | flags bit0/bit1 (prev/next cabinet) の ASCIIZ 文字列を skip して解釈 | MS-CAB §2.1 | ✅ | `parses_cabinet_with_prev_next_names` |
| 4 | flags bit2 (RESERVE_PRESENT): cbCFHeader/cbCFFolder/cbCFData による reserved 領域 skip | MS-CAB §2.1 | ✅ | `parses_cabinet_with_nonzero_reserve` |
| 5 | CFFOLDER: coffCabStart / cCFDATA / typeCompress (type は下位バイト) | MS-CAB §2.2 | ✅ | `Folder` |
| 6 | CFFILE: cbFile / uoffFolderStart / iFolder / attribs / ASCIIZ 名。date / time は読み飛ばし | MS-CAB §2.3 | ✅ | `FileRec` |
| 7 | CFDATA: csum / cbData / cbUncomp + データ (cbCFData reserve 対応) | MS-CAB §2.4 | ✅ | `decompress_folder` |
| 8 | csum 非ゼロ時は CFDATA チェックサム (cbData|cbUncomp<<16 シード + LE u32 ワード XOR) を検証 | MS-CAB §2.4 | ✅ | `rejects_checksum_mismatch`, `checksum_covers_cfdata_reserve` (シード欠落・abReserve 未包含を修正済み) |

### 圧縮フォルダ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 9 | tcompTYPE_NONE (0): CFDATA は生データ | MS-CAB §3.1 | ✅ | `parses_stored_cabinet` |
| 10 | tcompTYPE_MSZIP (1): 各 CFDATA は `CK` シグネチャ + raw DEFLATE stream | MS-CAB §3.1 | ✅ | `parses_mszip_cabinet` |
| 11 | MSZIP の LZ77 window (32KiB) は同一フォルダ内の CFDATA ブロック間で継続 | MS-CAB §3.1 | ✅ | `mszip_history_spans_cfdata_blocks`, `mszip_cross_block_backreference_resolves` |
| 12 | cbUncomp と実出力サイズの不一致は reject | MS-CAB §2.4 | ✅ | `rejects_uncompressed_size_mismatch` |

### ファイル再構成

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | ファイルデータは iFolder の uoffFolderStart から開始し cbFile バイト | MS-CAB §2.3 | ✅ | `parses_stored_cabinet` |
| 14 | cbFile がフォルダ末尾を超える場合、後続フォルダの非圧縮データへ継続 | MS-CAB §2.3 | ✅ | `file_spans_two_folders` |
| 15 | iFolder の特殊値 (0xFFFD-0xFFFF: cabinet 横断) は Unsupported | MS-CAB §2.3 | ✅ | `rejects_spanned_file` |
| 16 | bounds 検査 (truncated header/data → エラー) | crate エラー規約 | ✅ | `rejects_truncated` |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | crate で組み立てた MSZIP `.cab` を `bsdtar` (libarchive) が展開 | system interop | ✅ | `test_mscab_bsdtar_interop` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 18 | magic `MSCF` で `.cab` を自動検出 | CLI detection | ✅ | `detect_mscab` |
| 19 | `archive extract` は entry を展開 | CLI semantics | ✅ | `extract.rs` の `Format::Mscab` アーム |
| 20 | fuzz algorithm `mscab` (self-regression 含む) | fuzz harness | ✅ | `fuzz/src/algorithms.rs`。fixture は stored のみ生成 (MSZIP/flags/csum パスは fuzz 対象外) |
| 21 | encode: 単一 cabinet・単一 folder の出力 (CFHEADER + CFFOLDER + CFFILE + CFDATA)。NONE は生ブロック、MSZIP は `CK` + raw DEFLATE (32KiB 履歴を block 越えで継承) | MS-CAB §2.1-2.2, §3.1 | ✅ | `stored_roundtrip`, `mszip_roundtrip`, `mszip_cross_block_history`, `file_spanning_blocks`, `test_mscab_encoder_roundtrip`, `test_mscab_encoder_bsdtar_interop` |
| 22 | encode: CFDATA csum を実値出力 (cbData/cbUncomp seed + payload) | MS-CAB §2.2 | ✅ | decoder csum 検証パス (`checksum`) が encode 出力で成立 |
| 22a | encode: `FLAG_RESERVE_PRESENT` + cbCFHeader/cbCFFolder/cbCFData の reserved 領域をゼロフィル出力 (csum は CFDATA reserve を含む) | MS-CAB §2.1, §2.2 | ✅ | `reserve_roundtrip_stored`, `reserve_roundtrip_mszip`, `reserve_wire_layout` (`MscabEncoder::reserve`) |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 23 | tcompTYPE_QUANTUM (2) | MS-CAB §3.1 | ❌ | Quantum codec の厳密仕様が MS-CAB 内に完結しない (cf. 対象外フォーマット一覧) |
| 24 | tcompTYPE_LZX (3) | MS-CAB §3.1 | ❌ | CAB 用 LZX は公開文書の既知誤記を正誤判定できず厳密実装不能 (同上) |
| 25 | multi-cabinet set (.set / disk spanning) | MS-CAB §2.1, §2.3 | ❌ | 他キャビネットのデータが必要なため単一ファイル reader/writer では再構成不能 |
| 26 | 属性 / 日時のファイルシステム復元 | MS-CAB §2.3 | ❌ | 展開時の metadata 適用は対象外 (アーカイブ抽出の範囲)。encode 側も date/time/attribs は 0 出力 |
