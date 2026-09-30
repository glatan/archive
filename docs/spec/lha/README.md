# lha (LHA / LZH)

| 項目 | 内容 |
|------|------|
| 基準仕様 | lha header documentation (apphead / lzh_note、GNU lha 系資料)。実参照: [LHa for UNIX `header.doc.md`](https://github.com/jca02266/lha/blob/master/header.doc.md) ([jca02266/lha](https://github.com/jca02266/lha)) + jLHA Notes (Michel Ishizuka、[Wayback index](https://web.archive.org/web/20080724142842/http://homepage1.nifty.com/dangan/en/Content/Program/Java/jLHA/Notes/Notes.html)) + Joe Jared `lzhformat.html` + [Just Solve Wiki: LHarc](http://justsolve.archiveteam.org/wiki/LHarc)。ローカルスナップショット: `docs/spec/sources/lha_header.doc.md`, `jlha_notes_*.html`, `lzhformat.html`。一次実装: [LHA 2.11 ソース (Vector fh002420)](https://www.vector.co.jp/download/file/dos/util/fh002420.html) |
| 形式概要 | `[u8/u16 header size][checksum?][method 5B][packed u32][orig u32][time u32][attr u8][level u8](level 別フィールド)[ext headers][data]` のエントリ列。終端は header size = 0 |
| 実装範囲 | level 0/1/2 の **`-lh0-` (stored) / `-lhd-` (directory)** のみ read/write (write は `LhaEncoder::with_level` で level 0/1/2 を選択)。LZH 系圧縮メソッド (`-lh1-` 〜 `-lh7-`、`-lzs-`、`-lz4-`、`-pm0-` 等) は intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| header level 0 | lha header documentation | ✅ | ✅ | |
| header level 1 / 2 | lha header documentation + LHa for UNIX header.c 実測 | ✅ | ✅ | ext header (0x01 filename / 0x02 dir、raw 0xff 区切り) |
| header level 3 | jLHA Notes Level3Header (`sources/jlha_notes_level3_header.html`、word-size u16 + 32bit サイズのワイヤー記述あり) + lhasa (ISC) が de facto 参照実装 | ❌ | ❌ | level byte 3 は reject |
| method `-lh0-` (stored) / `-lhd-` (dir) | lha header documentation | ✅ | `-lh0-` のみ ✅ | |
| LZH 圧縮メソッド (`-lh1-`〜`-lh7-`, `-lzs-`/`-lz4-`/`-lz5-`, `-pm0-`/`-pm2-`) | jLHA Notes CompressMethod (`sources/jlha_notes_compress_method.html`、辞書サイズ/threshold/max-match/静的・動的 Huffman のパラメータ表 — bit レベル仕様は未記述) + 一次実装 LHA 2.11 ソース (lh0-lh5/lzs/lz4/lz5) + lhasa (ISC) / compcol (MIT) が de facto decode 参照 | ❌ | ❌ | intentional scope: lh6/lh7 は LHA 2.55 以降の追加、pm* は PMarc 独自、lhx は UNLHA32 独自 |

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
| 9 | その他のメソッド (`-lh1-`〜`-lh7-`、`-lzs-`、`-lz4-`、`-pm*` 等) は `Error::Unsupported` | lha note | ✅ | `rejects_unsupported_method`, `test_lha_rejects_compressed_method` |
| 10 | entry CRC-16 (CRC-16/ARC、poly 0x8005 reflected) を検証、不一致は reject | lha note | ✅ | decode 内検証 |
| 11 | bounds 検査 (truncated header/data → エラー) | crate エラー規約 | ✅ | `test_lha_rejects_truncated` |
| 12 | filename は UTF-8 必須、NUL 混入は reject。raw `0xff` バイトは `/` に正規化 (ext payload 全般 + level-0/1 基本 name field)、基本 name field の `\` も `/` に変換 | crate エラー規約 | ✅ | `sanitize_name`, `sanitize_basic_name` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | `LhaEncoder::add_file` / `add_dir` / `encode`: level-0 `-lh0-`/`-lhd-` ヘッダを生成、name 1-255B・NUL/`\` なし。パス区切りは raw `0xff` に変換、dir エントリは末尾 `0xff` + attr `0x10` | lha note level-0 + header.c 実測 | ✅ | `level0_roundtrip` |
| 13a | `LhaEncoder::with_level(1|2)` / `encode_level`: level-1 は基本 name field に basename (230B 超は ext `0x01`)、packed フィールドは skip size、dir は ext `0x02` (raw `0xff` 区切り・末尾付き)。level-2 は u16 総サイズ (自身込み) + ext `0x00` header-CRC + filename ext 必須 + 下位 8bit 0 時 1B pad | lha note level-1/level-2 + header.c write_header_level1/write_header_level2 | ✅ | `level1_roundtrip`, `level2_roundtrip`, `level2_long_path`, `level1_long_basename_uses_ext`, `level2_zero_low_byte_padding` |
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
| 17 | offset 2 の `-l`-`-` マーカー + offset 20 の level byte (0-2) で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_lha` (サブコマンド配線の spawn 統合テスト基盤は未整備) |
| 18 | fuzz harness `lha` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Lha` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | LZH 系圧縮メソッドの decode は非対応 | ❌ | `-lh1-`〜`-lh7-`、`-lzs-`、`-lz4-`、`-pm0-`/`-pm2-` 等。`Error::Unsupported` を返す。de facto 参照実装は manifest `no_url_available` の `lhasa`/`compcol` (源流は Okumura lzhuf.c public domain)。decode oracle は Debian main の `lhasa`/`unar` |
| 20 | write の mtime は level 0/1 で DOS time、level 2 で UNIX time をそのまま格納。UNIX ext 0x50/0x51/0x54 は発行しない | ✅ | `level1_roundtrip`, `level2_roundtrip`, `level2_long_path`, `level_rejects_bad_level` |
| 21 | マルチボリューム/リンク属性/OS 別属性の解釈は非対応 | ❌ | header level 3 も非対応 (level byte 3 は reject)。level 3 の書面記述は jLHA Notes (`sources/jlha_notes_level3_header.html`)、de facto 実装は lhasa。multi-disk/spanning (ext header 0x39・SPAN mode) は `sources/lzhformat.html` が記述 |

### vendor 別拡張・拡張ヘッダの整理

LHA 系の「独自拡張」は出自が分散している。出典別に整理する (詳細: jLHA Notes 各ページ、`sources/jlha_notes_ext_header_list.html`)。

**header level**

| level | 出自 | 備考 |
|---|---|---|
| level 0 | オリジナル LHA (≤2.13、Yoshizaki) | DOS 時刻・基本ヘッダのみ |
| level 1 | LHA 2.x (拡張ヘッダチェーン導入) | `header.doc` 記載 |
| level 2 | LHA for UNIX 系 (UNIX 時刻・u16 総サイズ) | `header.doc` 記載 |
| level 3 | LHA 2.67 / LHA for OS/2 / UNLHA32.DLL が試行的に使用 (LHA 3.0 構想は中断) | `header.doc` 未記載、jLHA Notes Level3Header が唯一の書面記述。32bit サイズ制限が残る設計問題あり |

**method の出自**

| 系列 | method | 備考 |
|---|---|---|
| LArc (三木和彦) | `-lzs-` `-lz4-` `-lz5-` | `-lz4-` は stored |
| LHA 本家 (吉崎) | `-lh0-`〜`-lh7-` | lh3 は試作 (静的 Huffman 版 lh2)。2.11 ソースは lh0-5 + lzs/lz4/lz5 を収録、lh6/7 は後の版で追加 |
| PMarc | `-pm0-` `-pm1-` `-pm2-` | 別ツール独自、`-pm0-` は stored |
| UNLHA32 (Micco) | `-lhx-` | UNLHA32.DLL 独自 |

**拡張ヘッダ identifier のカテゴリ** (LHA for OS/2 同梱 `header.tex` 由来の分類 + jLHA の細分化)

| range | カテゴリ | 主な identifier |
|---|---|---|
| 0x00-0x3F | common | 0x00 header CRC、0x01 filename、0x02 dirname、0x39 multi-disk、0x3F comment |
| 0x40-0x4F | MS-DOS | 0x40 DOS attr、0x41 Windows FILETIME、0x42 4GiB 超 file size、0x48-0x4F 認証用 reserved |
| 0x50-0x5F | UNIX | 0x50 permission、0x51 uid/gid、0x52 group name、0x53 user name、0x54 time_t |
| 0x60-0x7F | その他 OS 依存 | 0x7D capsule (旧 0xFC、Mac 用)、0x7E OS/2 EA (旧 0xFD)、0x7F level-3 新属性 (1) |
| 0x80-0xFF | reserved | 0xC4-0xC8 圧縮 comment、0xFF level-3 新属性 (2) |

一次資料の所在: header.tex (LHA for OS/2 2.08、平松聡)、LHAHED15.ZIP (立花恵理子)、header.txt (UNLHA32.DLL、Micco)、jLHA Notes・lzhformat.html (ともにスナップショット済み)。

### 実装メモ

- level-0 エンコーダは MS-DOS 属性バイト `0x20` (archive、dir は `0x10`) を出力し、name field のパス区切りは raw `0xff`。タイムスタンプは generic MS-DOS datetime。
- level-1 エンコーダは基本ヘッダのみを `hsize` に計上し、packed フィールドには skip size (packed + ext バイト) を書く。basename が 230B を超えると name field は空にして ext `0x01` に移す。
- level-2 エンコーダは `u16` 総サイズ (自身込み) を書き、ext `0x00` header CRC-16 ブロックを発行する。総サイズの下位 8bit が 0 になるとき 1 バイト pad を追加する (終端マーカとの衝突回避)。
- dir エントリ (`-lhd-`) は filename 部を空にし、フルパスを ext `0x02` (level-0 は name field) に末尾区切り付きで書く。level-1/2 では OS id `U` を発行するが UNIX ext (0x50/0x51/0x54) は発行しない。
- level 0/1 の mtime フィールドは DOS time、level 2 は UNIX time をそのまま格納する。
