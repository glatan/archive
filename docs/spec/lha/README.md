# lha (LHA / LZH)

| 項目 | 内容 |
|------|------|
| 基準仕様 | lha header documentation (apphead / lzh_note、GNU lha 系資料)。実参照: [LHa for UNIX `header.doc.md`](https://github.com/jca02266/lha/blob/master/header.doc.md) ([jca02266/lha](https://github.com/jca02266/lha)) + [Just Solve Wiki: LHarc](http://justsolve.archiveteam.org/wiki/LHarc)。ローカルスナップショット: `docs/spec/sources/lha_header.doc.md` |
| 形式概要 | `[u8/u16 header size][checksum?][method 5B][packed u32][orig u32][time u32][attr u8][level u8](level 別フィールド)[ext headers][data]` のエントリ列。終端は header size = 0 |
| 実装範囲 | level 0/1/2 の **`-lh0-` (stored) / `-lhd-` (directory)** のみ read/write (write は `LhaEncoder::with_level` で level 0/1/2 を選択)。LZH 系圧縮メソッド (`-lh1-` 〜 `-lh7-`、`-lzs-`、`-lz4-`、`-pm0-` 等) は intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| header level 0 | lha header documentation | ✅ | ✅ | |
| header level 1 / 2 | lha header documentation + LHa for UNIX header.c 実測 | ✅ | ✅ | ext header (0x01 filename / 0x02 dir、raw 0xff 区切り) |
| header level 3 | header.doc 未記載。lhasa (ISC) が level 3 の de facto 参照実装 | ❌ | ❌ | level byte 3 は reject |
| method `-lh0-` (stored) / `-lhd-` (dir) | lha header documentation | ✅ | `-lh0-` のみ ✅ | |
| LZH 圧縮メソッド (`-lh1-`〜`-lh7-`, `-lzs-`/`-lz4-`/`-lz5-`, `-pm0-`/`-pm2-`) | 書面仕様なし。lhasa (ISC) / compcol (MIT) が de facto decode 参照 | ❌ | ❌ | intentional scope: lh1/lh2/lh4-lh7 + LArc (lzs/lz4/lz5) + PMarc (pm0-pm2) + lhx を全網羅する参照実装あり |

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
| 21 | マルチボリューム/リンク属性/OS 別属性の解釈は非対応 | ❌ | header level 3 も非対応 (level byte 3 は reject)。level 3 は header.doc 未記載だが lhasa が de facto 参照実装 |

### 実装メモ

- level-0 エンコーダは MS-DOS 属性バイト `0x20` (archive、dir は `0x10`) を出力し、name field のパス区切りは raw `0xff`。タイムスタンプは generic MS-DOS datetime。
- level-1 エンコーダは基本ヘッダのみを `hsize` に計上し、packed フィールドには skip size (packed + ext バイト) を書く。basename が 230B を超えると name field は空にして ext `0x01` に移す。
- level-2 エンコーダは `u16` 総サイズ (自身込み) を書き、ext `0x00` header CRC-16 ブロックを発行する。総サイズの下位 8bit が 0 になるとき 1 バイト pad を追加する (終端マーカとの衝突回避)。
- dir エントリ (`-lhd-`) は filename 部を空にし、フルパスを ext `0x02` (level-0 は name field) に末尾区切り付きで書く。level-1/2 では OS id `U` を発行するが UNIX ext (0x50/0x51/0x54) は発行しない。
- level 0/1 の mtime フィールドは DOS time、level 2 は UNIX time をそのまま格納する。
