# lha (LHA / LZH)

| 項目 | 内容 |
|------|------|
| 基準仕様 | lha header documentation (apphead / lzh_note、GNU lha 系資料)。実参照: [LHa for UNIX `header.doc.md`](https://github.com/jca02266/lha/blob/master/header.doc.md) ([jca02266/lha](https://github.com/jca02266/lha)) + jLHA Notes (Michel Ishizuka 氏、[Wayback index](https://web.archive.org/web/20080724142842/http://homepage1.nifty.com/dangan/en/Content/Program/Java/jLHA/Notes/Notes.html)) + Joe Jared `lzhformat.html` + [Just Solve Wiki: LHarc](http://justsolve.archiveteam.org/wiki/LHarc)。ローカルスナップショット: `docs/spec/sources/lha_header.doc.md`, `jlha_notes_*.html`, `lzhformat.html`, `ar002_*` (`ar002_00README.txt`/`ar002_ar.h`/`ar002_decode.c`/`ar002_huf.c`/`ar002_maketbl.c`/`ar002_compr.txt`/`ar002_compr2.txt`), `lzss.c`。一次実装: [LHA 2.11 ソース (Vector fh002420)](https://www.vector.co.jp/download/file/dos/util/fh002420.html) |
| 参照実装 | 奥村晴彦氏の `ar002` (public domain、`-lh4-`〜`-lh7-` st1 形式の format reference、`sources/ar002_*`)、奥村氏の `lzss.c` (public domain、`-lzs-` の一次参照、`sources/lzss.c`)、lhasa (ISC、`-lz5-` format reference + `pmarc.rs` 移植元 + fixture vendor + oracle)。LHA 2.11 / LHa for UNIX 1.14i は `header.doc.md` 書面参照 + fixture 生成のみ (コード由来なし。LHa ライセンスは binary-only 再配布禁止・商用主利用禁止の非 OSI 条件)。XADMaster / deark 由来コードは `-lh1-`〜`-lh3-` 実装削除により除去済み。system `lhasa` / `unar` / `lha` / `7z` / `bsdtar` は interop oracle。詳細: THIRD_PARTY_NOTICES lha 項・§4a |
| 形式概要 | `[u8/u16 header size][checksum?][method 5B][packed u32][orig u32][time u32][attr u8][level u8](level 別フィールド)[ext headers][data]` のエントリ列。終端は header size = 0 |
| 実装範囲 | header level 0-3 の読み込み、`-lh0-` (stored) / `-lhd-` (dir) / `-lh4-`〜`-lh7-` / LArc `-lzs-`/`-lz4-`/`-lz5-` / PMarc `-pm0-`〜`-pm2-` のデコードに対応する。`-lh1-`〜`-lh3-` は権利クリーンな format 参照が存在しないため意図的に非対応 (`Error::Unsupported`)。書き込みは header level 0-3 (`with_level`) と、圧縮メソッド `-lh0-`/`-lhd-`/`-lh4-`〜`-lh7-`、LArc `-lzs-`/`-lz5-`、および無圧縮エイリアス `-lz4-`/`-pm0-` (`with_method`) に対応する |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| header level 0 | lha header documentation | ✅ | ✅ | |
| header level 1 / 2 | lha header documentation + LHa for UNIX header.c 実測 | ✅ | ✅ | ext header (0x01 filename / 0x02 dir、raw 0xff 区切り) |
| header level 3 | jLHA Notes Level3Header (`sources/jlha_notes_level3_header.html`) + lhasa (ISC) | ✅ | ✅ | `with_level(3)` で write 対応 (`emit_level3`)。32 バイト基本ヘッダ + u32 サイズ + u32 ext チェーン |
| method `-lh0-` (stored) / `-lhd-` (dir) | lha header documentation | ✅ | `-lh0-` のみ ✅ | |
| LZH 圧縮メソッド (`-lh4-`〜`-lh7-`, `-lzs-`/`-lz4-`/`-lz5-`, `-pm0-`〜`-pm2-`) | `-lh4-`〜`-lh7-`: 奥村氏の `ar002` (public domain、`sources/ar002_*`)。`-lzs-`: 奥村氏の `lzss.c` (public domain、`sources/lzss.c`)。`-lz5-`/PMarc: lhasa (ISC) が権利クリーン参照。de facto パラメタは lhasa と一致 | ✅ | ⚠️ | encode は st1 系 `-lh4-`〜`-lh7-` (`with_method` 経由で `compress::lzh::st1_enc`)、LArc `-lzs-`/`-lz5-` (`larc_enc::{encode_lzs,encode_lz5}`)、および無圧縮エイリアス `-lz4-`/`-pm0-` に対応する (`lzs_encode_roundtrip`, `lz5_encode_roundtrip`, `test_lha_lzs_lz5_bsdtar_interop`)。`-pm1-`/`-pm2-` の圧縮 write は未対応。`-lh1-`〜`-lh3-`・`-lhx-` (UNLHA32 独自) などの非対応メソッドは decode 側でも `Error::Unsupported` を返す |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | level 0: `[hdr_size u8][cksum u8][method][packed][orig][dos time][attr][level=0][name_len u8][name][crc16 u16le]`、hdr_size は method〜crc16 範囲のバイト数 | lha note level-0 | ✅ | `level0_roundtrip` |
| 2 | level 0/1 の checksum は header 本体の byte-sum & 0xff、不一致は reject | lha note | ✅ | `rejects_bad_checksum` |
| 3 | level 1: `hsize` は基本ヘッダのみ (name + crc16 + OS id + 先頭 `u16` next-size まで)。ext チェーン (`u16 size` 自身込み + `u8 type` + data) は基本ヘッダの後に続き、packed size フィールドは skip size (packed + ext バイト) | lha note level-1 + header.c get_header_level1 | ✅ | `level1_real_archive`, `level1_real_nested_dir` |
| 4 | level 2: `[u16le total hdr size][method][packed][orig][unix time][0x20][level=2][crc16][OS id][ext headers]`、total size は u16 自身を含む。filename は ext `0x01`、directory は ext `0x02` (raw `0xff` 区切り → `/`)、ext `0x00` は header CRC-16。末尾 1 バイト pad 許容 | lha note level-2 + header.c get_header_level2 | ✅ | `level2_decode`, `level2_real_archive`, `level2_real_nested_dir` |
| 5 | 終端は header size 0 (level 0/1: `u8` 0、level 2 後続でも 0 バイト)。EOF 到達も許容 | lha note | ✅ | 往復テスト |
| 6 | header level は record 先頭から offset 20 の level byte で判定 | lha note | ✅ | decode ディスパッチ |

### メソッド / データ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | `-lh0-`: data は生バイト列、packed size == orig size 必須 | lha note | ✅ | `level0_roundtrip` |
| 8 | `-lhd-`: directory marker、payload なしで `is_dir` | lha note | ✅ | `dir_entry` |
| 9 | 未対応メソッド (`-lhx-` 等、実装済み以外の `-l??-`) は `Error::Unsupported` | lha note | ✅ | `rejects_unsupported_method` |
| 10 | entry CRC-16 (CRC-16/ARC、poly 0x8005 reflected) を検証、不一致は reject | lha note | ✅ | decode 内検証 |
| 11 | bounds 検査 (truncated header/data → エラー) | crate エラー規約 | ✅ | `test_lha_rejects_truncated` |
| 12 | filename は UTF-8 必須、NUL 混入は reject。raw `0xff` バイトは `/` に正規化 (ext payload 全般 + level-0/1 基本 name field)、基本 name field の `\` も `/` に変換 | crate エラー規約 | ✅ | `sanitize_name`, `sanitize_basic_name` |


### 圧縮メソッド decode

| method | アルゴリズム | 履歴バッファ | 状態 | テスト/fixture |
|---|---|---|---|---|
| `-lh0-` | stored (無圧縮) | - | ✅ | `level0_roundtrip` |
| `-lh1-` | 適応 Huffman + LZ77 (吉崎氏の lzhuf、奥村氏訳注) | 4 KiB | ❌ | **意図的非対応**: `lzhuf.c` は明示的ライセンス供与なし。fixture `lh1.lzh, lh1_lharc.lzh` は reject 入力 (`test_lha_legacymethod_rejection`) |
| `-lh2-` | 動的 Huffman + LZ77 (LHa dhuf) | 8 KiB | ❌ | **意図的非対応**: `dhuf.c` は LHa 独自ライセンス (binary-only 再配布禁止・商用主利用禁止、非 OSI)。fixture `lh2.lzh` は reject 入力 |
| `-lh3-` | 静的 Huffman st0 + LZ77 (LHa shuf) | 8 KiB | ❌ | **意図的非対応**: `shuf.c` 同上。fixture `lh3.lzh` は reject 入力 |
| `-lh4-` | 静的 Huffman st1 + LZ77 (ar002 形式) | 16 KiB (de facto) | ✅ | `lh4.lzh` |
| `-lh5-` | 静的 Huffman st1 + LZ77 (ar002 形式) | 16 KiB (de facto) | ✅ | `lh5.lzh, lh5_255e.lzh, h3_lh5.lzh` |
| `-lh6-` | 静的 Huffman st1 + LZ77 (ar002 拡張パラメタ) | 64 KiB (de facto) | ✅ | `lh6.lzh, h2_lh6.lzh` |
| `-lh7-` | 静的 Huffman st1 + LZ77 (ar002 拡張パラメタ) | 128 KiB (de facto) | ✅ | `lh7.lzh, h2_lh7.lzh` |
| `-lzs-` | LArc ビット指向 LZSS | 2 KiB | ✅ | `lzs.lzh` |
| `-lz4-` | LArc stored (無圧縮) | - | ✅ | `lz4.lzh, lz4.lzs` |
| `-lz5-` | LArc バイト指向 LZSS | 4 KiB | ✅ | `lz5.lzh, lz5.lzs, long.lzs` |
| `-pm0-` | PMarc stored (無圧縮) | - | ✅ | `pm0.lzh, pm0.pma` |
| `-pm1-` | PMarc 静的木 + MTF + LZ | 8 KiB | ✅ | `pm1.lzh, pm1.pma, pm1_long.pma, mtcd.pma` |
| `-pm2-` | PMarc 動的木 + MTF + LZ | 8 KiB | ✅ | `pm2.lzh, pm2.pma, long.pma` |
| `-lhd-` | directory marker (payload なし) | - | ✅ | `dir_entry` |

fixture は全て `tests/fixtures/lha/` 配下。統合テスト: `test_lha_compressed_method_fixtures`, `test_lha_level3_fixtures`, `test_lha_fixture_oracle_extract`, `test_lha_legacymethod_rejection`。
decode の権利クリーン参照: `-lh4-`〜`-lh7-` は奥村氏の `ar002` (public domain、`sources/ar002_huf.c`/`ar002_maketbl.c`)、`-lzs-` は奥村氏の `lzss.c` (public domain)、`-lz5-`/`-pm1-`/`-pm2-` は lhasa (ISC)。`-lh1-`〜`-lh3-` は参照実装の権利状態が不確実なため非対応 (上表)。

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | `LhaEncoder::add_file` / `add_dir` / `encode`: level-0 `-lh0-`/`-lhd-` ヘッダを生成、name 1-255B・NUL/`\` なし。パス区切りは raw `0xff` に変換、dir エントリは末尾 `0xff` + attr `0x10` | lha note level-0 + header.c 実測 | ✅ | `level0_roundtrip` |
| 13a | `LhaEncoder::with_level(1|2)` / `encode_level`: level-1 は基本 name field に basename (230B 超は ext `0x01`)、packed フィールドは skip size、dir は ext `0x02` (raw `0xff` 区切り・末尾付き)。level-2 は u16 総サイズ (自身込み) + ext `0x00` header-CRC + filename ext 必須 + 下位 8bit 0 時 1B pad | lha note level-1/level-2 + header.c write_header_level1/write_header_level2 | ✅ | `level1_roundtrip`, `level2_roundtrip`, `level2_long_path`, `level1_long_basename_uses_ext`, `level2_zero_low_byte_padding` |
| 13b | `LhaEncoder::with_level(3)`: `[u16 word_size=4][method][u32 packed][u32 orig][u32 unix time][0x20][level=3][u16 crc16][u8 osid][u32 hsize][u32 ext chain][u32 0]` (ext 順序: 0x00 header-CRC → 0x01 filename → 0x02 dir)。`with_method`: `-lh4-`〜`-lh7-` を st1 共有エンコーダ (`compress::lzh::st1_enc`) で圧縮、stored alias `-lz4-`/`-pm0-`、圧縮不利時は `-lh0-` fallback | jLHA Notes Level3Header + lhasa 実測 | ✅ | `level3_roundtrip`, `level3_wire_layout`, `level3_long_name`, `lh5_encode_roundtrip`, `lh4_lh6_lh7_encode_roundtrip`, `lh5_falls_back_to_stored`, `stored_alias_methods_roundtrip` |
| 14 | 終端 `0x00` を付与 | lha note | ✅ | 往復テスト |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | crate 生成 level-0 / level-1 / level-2 `.lzh` を `bsdtar` (libarchive) が list/extract | system interop | ✅ | `test_lha_bsdtar_list_interop`, `test_lha_level1_bsdtar_interop`, `test_lha_level2_bsdtar_interop` |
| 16 | crate 生成 level-0 / level-1 / level-2 `.lzh` を `7z` が list/extract | system interop | ✅ | `test_lha_7z_list_interop`, `test_lha_level1_7z_interop`, `test_lha_level2_7z_interop` |
| 16a | 参照実装 LHa for UNIX 生成の level-1/2 `.lzh` を decode (fixture: tests/fixtures/lha/)、crate 生成 level-0/1/2 は LHa で展開確認済み (手動) | system interop | ✅ | `level1_real_archive`, `level2_real_archive`, `level1_real_nested_dir`, `level2_real_nested_dir` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | offset 2 の `-l?-` または `-pm?-` マーカー + offset 20 の level byte (0-3) で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_lha` |
| 18 | fuzz harness `lha` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Lha` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | 圧縮メソッドの write は st1 系および LArc `-lzs-`/`-lz5-` のみ対応 | ⚠️ | `with_method` は `-lh4-`〜`-lh7-`、`-lzs-`/`-lz5-`、および無圧縮エイリアス `-lz4-`/`-pm0-` を受理する (`larc_enc`)。`-lh1-`〜`-lh3-` および `-pm1-`/`-pm2-` の圧縮 write は未対応。`-lh1-`〜`-lh3-` (権利クリーン参照不在)・`-lhx-` などの非対応メソッドの decode は `Error::Unsupported` を返す |
| 20 | write の mtime は level 0/1 で DOS time、level 2 で UNIX time をそのまま格納。UNIX ext 0x50/0x51/0x54 は発行しない | ✅ | `level1_roundtrip`, `level2_roundtrip`, `level2_long_path`, `level_rejects_bad_level` |
| 21 | マルチボリューム/リンク属性/OS 別属性の解釈は非対応 | ❌ | header level 3 は read/write 対応済み (`with_level(3)`)。multi-disk/spanning (ext header 0x39・SPAN mode) は `sources/lzhformat.html` が記述 |

### vendor 別拡張・拡張ヘッダの整理

LHA 系の「独自拡張」は出自が分散している。出典別に整理する (詳細: jLHA Notes 各ページ、`sources/jlha_notes_ext_header_list.html`)。

**header level**

| level | 出自 | 備考 |
|---|---|---|
| level 0 | オリジナル LHA (≤2.13、吉崎氏) | DOS 時刻・基本ヘッダのみ |
| level 1 | LHA 2.x (拡張ヘッダチェーン導入) | `header.doc` 記載 |
| level 2 | LHA for UNIX 系 (UNIX 時刻・u16 総サイズ) | `header.doc` 記載 |
| level 3 | LHA 2.67 / LHA for OS/2 / UNLHA32.DLL が試行的に使用 (LHA 3.0 構想は中断) | `header.doc` 未記載、jLHA Notes Level3Header が唯一の書面記述。32bit サイズ制限が残る設計問題あり |

**method の出自**

| 系列 | method | 備考 |
|---|---|---|
| LArc (三木和彦氏) | `-lzs-` `-lz4-` `-lz5-` | `-lz4-` は stored。全 method decode 対応 |
| LHA 本家 (吉崎氏) | `-lh0-`〜`-lh7-` | lh3 は試作 (静的 Huffman 版 lh2)。`-lh1-`〜`-lh3-` は権利クリーン参照不在のため意図的非対応、`-lh0-`/`-lh4-`〜`-lh7-` は decode 対応 |
| PMarc | `-pm0-` `-pm1-` `-pm2-` | 別ツール独自、`-pm0-` は stored。全 method decode 対応 |
| UNLHA32 (Micco 氏) | `-lhx-` | UNLHA32.DLL 独自。非対応 |

**拡張ヘッダ identifier のカテゴリ** (LHA for OS/2 同梱 `header.tex` 由来の分類 + jLHA の細分化)

| range | カテゴリ | 主な identifier |
|---|---|---|
| 0x00-0x3F | common | 0x00 header CRC、0x01 filename、0x02 dirname、0x39 multi-disk、0x3F comment |
| 0x40-0x4F | MS-DOS | 0x40 DOS attr、0x41 Windows FILETIME、0x42 4GiB 超 file size、0x48-0x4F 認証用 reserved |
| 0x50-0x5F | UNIX | 0x50 permission、0x51 uid/gid、0x52 group name、0x53 user name、0x54 time_t |
| 0x60-0x7F | その他 OS 依存 | 0x7D capsule (旧 0xFC、Mac 用)、0x7E OS/2 EA (旧 0xFD)、0x7F level-3 新属性 (1) |
| 0x80-0xFF | reserved | 0xC4-0xC8 圧縮 comment、0xFF level-3 新属性 (2) |

一次資料の所在: header.tex (LHA for OS/2 2.08、平松聡氏)、LHAHED15.ZIP (立花恵理子氏)、header.txt (UNLHA32.DLL、Micco 氏)、jLHA Notes・lzhformat.html (ともにスナップショット済み)。

- 履歴バッファ (window) サイズは **de facto (lhasa 系) の st1 パラメタに従う**: `-lh4-`/`-lh5-` = 16 KiB (hist_bits 14)、`-lh6-` = 64 KiB (16)、`-lh7-` = 128 KiB (17)。元祖 LHa for UNIX の定数 (`lha_macro.h`) は `-lh4-`=4 KiB (dicbit 12) / `-lh5-`=8 KiB (13) / `-lh6-`=32 KiB (15) / `-lh7-`=64 KiB (16) であり正典値が一意でない。lhasa は `-lh4-` と `-lh5-` を同一 decoder (14bit) で処理する。wire 上は offset code の range が広いだけで、旧来の小さい window で書かれたストリームは大きい ring で後方互換に decode されるため、本 crate は lhasa 値を採用する (実装: `st1.rs` の `hist_bits` 表)。bitstream 構造 (block 頭の 16bit command count + temp/main/offset 3 テーブル + alphabet 510 + `distance = (1<<(j-1)) + getbits(j-1)`) は奥村氏の `ar002` (PD) が一次定義。
- **encoder window の既知制約**: `st1_enc` は `window = 1 << hist_bits` で greedy parse するため、`-lh5-` で最大 16383 の distance を出力しえる。元祖 LHa for UNIX 系 decoder (de jure 値: `-lh5-`=8 KiB ring、`-lh6-`=32 KiB、`-lh7-`=64 KiB) は自身の window を超える distance を正しく decode できない可能性があるため、本 crate が emit するアーカイブは **現代の decoder (lhasa 系 16/64/128 KiB、本 crate 自身) では正しいが、厳密な旧実装との相互運用は保証しない**。wire format 自体は ar002 の alphabet 範囲内で合法であり、現行挙動はこの割り切りを意図的に維持する (旧実装互換が必要になった場合は encoder window を de jure 値に制限する修正が必要)。

### 実装メモ

- level-0 エンコーダは MS-DOS 属性バイト `0x20` (archive、dir は `0x10`) を出力し、name field のパス区切りは raw `0xff`。タイムスタンプは generic MS-DOS datetime。
- level-1 エンコーダは基本ヘッダのみを `hsize` に計上し、packed フィールドには skip size (packed + ext バイト) を書く。basename が 230B を超えると name field は空にして ext `0x01` に移す。
- level-2 エンコーダは `u16` 総サイズ (自身込み) を書き、ext `0x00` header CRC-16 ブロックを発行する。総サイズの下位 8bit が 0 になるとき 1 バイト pad を追加する (終端マーカとの衝突回避)。
- dir エントリ (`-lhd-`) は filename 部を空にし、フルパスを ext `0x02` (level-0 は name field) に末尾区切り付きで書く。level-1/2 では OS id `U` を発行するが UNIX ext (0x50/0x51/0x54) は発行しない。
- level 0/1 の mtime フィールドは DOS time、level 2/3 は UNIX time をそのまま格納する。
- level-3 エンコーダは先頭 `u16 word_size=4` (固定) + u32 packed/orig + u32 ext チェーン (0x00 header-CRC → 0x01 filename → 0x02 dir の順、各エントリの u32 size は size フィールド自身 + type + payload を含む) を出力し、packed フィールドには実バイト数 (skip size ではない) を書く。
- 圧縮メソッドエンコーダ (`with_method` の `-lh4-`〜`-lh7-`) は `compress::lzh::st1_enc` 共有実装 (greedy hash-chain + 頻度ベース Huffman、ARJ method 1-3 と共用)。stored alias `-lz4-`/`-pm0-` は wire 上 `-lh0-` と同型のためタグのみ付け替えて受理する。encoder の window は de facto (lhasa) 値で動作し、元祖 LHa decoder の de jure window を超える distance を emit しえる点は上記「encoder window の既知制約」を参照。
