# mscab (Microsoft Cabinet)

| 項目 | 内容 |
|------|------|
| 基準仕様 | [[MS-CAB]](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) Cabinet File Format (Microsoft Open Specifications、2011-03-04 版 PDF。HTML 版: <https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10)>、ローカルスナップショット: `docs/spec/sources/ms-cab_20110304.pdf`) |
| 参照実装 | libmspack / cabextract (LGPL-2.1、Quantum `qtmd.c` の移植元・LZX `lzx.c` errata と checksum の動作参照・fixture 由来)、compcol (MIT、Quantum 移植の中間参照)。`bsdtar`/`cabextract` は統合テストの oracle。詳細: THIRD_PARTY_NOTICES mscab 項 |
| 形式概要 | CFHEADER + CFFOLDER 配列 + CFFILE 配列 + CFDATA ブロック列。フォルダ単位で圧縮 |
| 実装範囲 | read/write (単一 cabinet・単一 folder の NONE/MSZIP) + LZX/Quantum folder の read + `decode_parts` による multi-cabinet set read。LZX/Quantum write / multi-cabinet write は intentional scope 外 |

参照: <https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf>

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| compression NONE | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) | ✅ | ✅ | 単一 folder write |
| compression MSZIP | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) + [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951.txt) | ✅ | ✅ | `compress::deflate` 再利用 (`mszip_roundtrip` 等) |
| compression Quantum | MS-CAB (名称のみ) + de facto 参照: libmspack `qtmd.c` (LGPL-2.1)、compcol (MIT)、unquantum 解説 | ✅ | — | adaptive arithmetic coder + LZ。encode は公開 encoder が一切存在せず恒久的対象外 |
| compression LZX | MS "LZX Format" doc + cabextract `lzx.c` errata | ✅ | — | `compress::lzx` (lzxd とコア共有)。window bits 15-21、cabextract fixture で検証 |
| multi-cabinet set | [MS-CAB](https://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/%5Bms-cab%5D.pdf) | ✅ | ❌ | `decode_parts(&[&[u8]])` が set メンバーを順に連結 (iCabinet/setID 検証、folder fragment 連結・CFDATA 分割再構成)。write は単一キャビネットのみ |

### ヘッダ / エントリ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | CFHEADER: magic `MSCF`、reserved フィールド、cbCabinet、coffFiles、cFolders、cFiles、flags (全て LE)。setID / iCabinet は parse 対象だが単一 cabinet decode ではバリデーション対象外 (`decode_parts` で index/setID 整合を検証) | MS-CAB §2.1 | ✅ | `parses_stored_cabinet` |
| 1a | CFHEADER version: `versionMajor`==1 必須、`versionMinor`>3 は拒否 | MS-CAB §2.1 | ✅ | `rejects_bad_major_version`, `rejects_bad_minor_version` |
| 2 | version 1.x (major=1, minor<=3) を受理、それ以外は reject | MS-CAB §2.1 | ✅ | `rejects_bad_major_version`, `rejects_bad_minor_version` |
| 3 | flags bit0/bit1 (prev/next cabinet) の ASCIIZ 文字列を skip して解釈 | MS-CAB §2.1 | ✅ | `parses_cabinet_with_prev_next_names` |
| 4 | flags bit2 (RESERVE_PRESENT): cbCFHeader/cbCFFolder/cbCFData による reserved 領域 skip | MS-CAB §2.1 | ✅ | `parses_cabinet_with_nonzero_reserve` |
| 5 | CFFOLDER: coffCabStart / cCFDATA / typeCompress (type は下位バイト) | MS-CAB §2.2 | ✅ | `Folder` |
| 6 | CFFILE: cbFile / uoffFolderStart / iFolder / attribs / date / time / ASCIIZ 名 | MS-CAB §2.3 | ✅ | `MscabEntry::{attribs,date,time}` で生値を公開 (`FileRec`) |
| 7 | CFDATA: csum / cbData / cbUncomp + データ (cbCFData reserve 対応) | MS-CAB §2.4 | ✅ | `decompress_folder` |
| 8 | csum 非ゼロ時は CFDATA チェックサム (cbData|cbUncomp<<16 シード + LE u32 ワード XOR) を検証 | MS-CAB §2.4 | ✅ | `rejects_checksum_mismatch`, `checksum_covers_cfdata_reserve` (シード欠落・abReserve 未包含を修正済み) |

### 圧縮フォルダ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 9 | tcompTYPE_NONE (0): CFDATA は生データ | MS-CAB §3.1 | ✅ | `parses_stored_cabinet` |
| 10 | tcompTYPE_MSZIP (1): 各 CFDATA は `CK` シグネチャ + raw DEFLATE stream | [MS-MCI] (MS-CAB は圧縮内部形式を委譲) | ✅ | `parses_mszip_cabinet` |
| 11 | MSZIP の LZ77 window (32KiB) は同一フォルダ内の CFDATA ブロック間で継続 | [MS-MCI] + de facto | ✅ | `mszip_history_spans_cfdata_blocks`, `mszip_cross_block_backreference_resolves` |
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
| 22a | encode: `FLAG_RESERVE_PRESENT` + cbCFHeader/cbCFFolder/cbCFData の reserved 領域をゼロフィル出力 (csum は CFDATA reserve を含む) | MS-CAB §2.1, §2.2 | ✅ | `reserve_roundtrip_stored`, `reserve_roundtrip_mszip`, `reserve_wire_layout` (`MscabEncoder::reserve`; cbCFHeader 上限 60,000 は `finish` で検証 `reserve_rejects_oversize_header`) |
| 24 | tcompTYPE_LZX (3): CFFOLDER typeCompress 上位 window bits (15-21) で window 決定、CFDATA 列を連続 bitstream として LZX 展開 (folder 内 window 継続・multi-cabinet fragment 連結対応) | [MS-MCI] + MS "LZX Format" doc (+cabextract `lzx.c` errata) | ✅ | `compress::lzx::decode_cabinet` (lzxd コア共有)。`cab_*`, `parses_lzx_cabinet`, `lzx_stream_spans_cfdata_blocks`, `lzx_window_size_bits`, `test_mscab_lzx_fixture`, `test_mscab_lzx_large_fixture` |
| 23 | tcompTYPE_QUANTUM (2): typeCompress 上位 window bits (10-21) で window 決定、CFDATA 列を連続 bitstream + 各 block 後の synthesize 0xFF sentinel として Quantum 展開 | [MS-MCI] + de facto 参照 (manifest `no_url_available` の `libmspack-quantum`/`compcol`、Matthew Russotto 逆解析) | ✅ | `archive::mscab::quantum`。`decodes_real_text_stream`, `decodes_single_frame`, `decodes_multi_frame`, `decodes_quantum_folder`, `test_mscab_quantum_fixture` (実 cab: 16 blocks/524159B zeros), `test_mscab_quantum_synthesized_cab`, `test_mscab_quantum_cabextract_interop`。公開 encoder は存在しないため encode は恒久的対象外 |

### その他要件

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 25 | multi-cabinet set (.set / disk spanning) read | MS-CAB §2.1, §2.3 | ✅ | `decode_parts` が iCabinet 順の member 列を受理 (index/setID 不一致は reject)。iFolder 0xFFFD/0xFFFE/0xFFFF と cbUncomp==0 CFDATA 分割を解決 (continued entry の dedup は name+cbFile 一致で判定、CFHEADER の PREV/NEXT flag 自体は内容を解決に使わないため未検証)。`decode_parts_split_file`, `decode_parts_cfdata_block_split`, `decode_parts_set_id_mismatch`, `decode_parts_index_mismatch`, `decode_parts_missing_earlier_member`, `decode_parts_rejects_empty` |
| 27 | §1.3 フォーマット上限群 (file ≤0x7FFF8000、folder data ≤0x7FFF8000、count ≤0xFFFF、cab ≤0x7FFFFFFF) の検証 + CFFILE szName ≤256B+NUL の encoder 検証 + CFFILE 順序規則 (iFolder→uoffFolderStart、continued-from-prev 先頭) | MS-CAB §1.3, §2.3 | ❌ | encoder は cFolders/cFiles の u16 上限のみ検証。バイト上限・szName 256B 上限・明示的な CFFILE 順序検証は未実装 (decoder は範囲検査で充足、`decode_parts` は順序前提で動作)。flags 上位 reserved bit の "MUST be ignored" は decoder 無視で充足 |

### Intentional scope (実装対象外)

| # | 要件 | 仕様参照 | 状態 | 備考 |
|---|------|----------|-----------|------|
| 26 | 属性 / 日時のファイルシステム復元 | MS-CAB §2.3 | ✅ | 生の値は `MscabEntry::date` / `time` / `attribs` で公開する (`exposes_cffile_date_time_attribs`)。encode 側は `MscabFileMeta` + `MscabEncoder::add_file_with_meta` で date/time/attribs を emit 可能 (`add_file` は従来通り 0 emit。`encoder_emits_date_time_attribs` で roundtrip 検証)。ファイルシステムへの属性復元はアーカイブ抽出層の責務として intentional scope 外とする。attribs bit0x80 (`_A_NAME_IS_UTF`) は flag 有無に関わらず名を常に `from_utf8_lossy` で解釈する方針 (ASCII は UTF-8 に含まれるため安全側) |
