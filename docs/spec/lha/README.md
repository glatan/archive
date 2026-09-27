# lha (LHA / LZH)

| 項目 | 内容 |
|------|------|
| 基準仕様 | lha header documentation (apphead / lzh_note、GNU lha 系資料) |
| 形式概要 | `[u8/u16 header size][checksum?][method 5B][packed u32][orig u32][time u32][attr u8][level u8](level 別フィールド)[ext headers][data]` のエントリ列。終端は header size = 0 |
| 実装範囲 | level 0/1/2 の **`-lh0-` (stored) / `-lhd-` (directory)** のみ read。write は level-0 `-lh0-` のみ。LZH 系圧縮メソッド (`-lh1-` 〜 `-lh7-`、`-lzs-`、`-lz4-`、`-pm0-` 等) は intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| header level 0 | lha header documentation | ✅ | ✅ | write は level-0 `-lh0-` のみ |
| header level 1 / 2 | lha header documentation | ✅ | ❌ | ext header (0x01 filename / 0x02 dir) 対応 |
| header level 3 | lha header documentation | ❌ | ❌ | level byte 3 は reject |
| method `-lh0-` (stored) / `-lhd-` (dir) | lha header documentation | ✅ | `-lh0-` のみ ✅ | |
| LZH 圧縮メソッド (`-lh1-`〜`-lh7-`, `-lzs-`/`-lz4-`/`-lz5-`, `-pm0-`/`-pm2-`) | lha header documentation | ❌ | ❌ | intentional scope: 圧縮内部の書面仕様なし |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | level 0: `[hdr_size u8][cksum u8][method][packed][orig][dos time][attr][level=0][name_len u8][name][crc16 u16le]`、hdr_size は method〜crc16 範囲のバイト数 | lha note level-0 | ✅ | `level0_roundtrip` |
| 2 | level 0/1 の checksum は header 本体の byte-sum & 0xff、不一致は reject | lha note | ✅ | `rejects_bad_checksum` |
| 3 | level 1: filename + `crc16` + OS id + extended header チェーン (`u16 size` 自身込み + `u8 type` + data) | lha note level-1 | ✅ | ext 解析処理 (`walk_ext_headers`) |
| 4 | level 2: `[u16le total hdr size][method][packed][orig][unix time][0x20][level=2][crc16][OS id][ext headers]`、filename は ext 0x01、directory は ext 0x02 (0xff 区切り → `/`) | lha note level-2 | ✅ | `level2_decode` |
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
| 12 | filename は UTF-8 必須、NUL 混入は reject (level-2 dir ext の 0xff は `/` に変換) | crate エラー規約 | ✅ | `sanitize_name` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 13 | `LhaEncoder::add_file` / `add_dir` / `encode`: level-0 `-lh0-`/`-lhd-` ヘッダを生成、name 1-255B・NUL なし | lha note level-0 | ✅ | `level0_roundtrip` |
| 14 | 終端 `0x00` を付与 | lha note | ✅ | 往復テスト |

### システム相互運用

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 15 | crate 生成 level-0 `.lzh` を `bsdtar` (libarchive) が list/extract | system interop | ✅ | `test_lha_bsdtar_list_interop` |
| 16 | crate 生成 level-0 `.lzh` を `7z` が list/extract | system interop | ✅ | `test_lha_7z_list_interop` |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 17 | offset 2 の `-l`-`-` マーカー + offset 20 の level byte (0-2) で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_lha` (サブコマンド配線の spawn 統合テスト基盤は未整備) |
| 18 | fuzz harness `lha` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Lha` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 19 | LZH 系圧縮メソッドの decode は非対応 | ❌ | `-lh1-`〜`-lh7-`、`-lzs-`、`-lz4-`、`-pm0-`/`-pm2-` 等。`Error::Unsupported` を返す |
| 20 | write は level-0 `-lh0-` のみ | ❌ | level-1/2 ヘッダの生成は非対応 |
| 21 | マルチボリューム/リンク属性/OS 別属性の解釈は非対応 | ❌ | header level 3 も非対応 (level byte 3 は reject) |

### 実装メモ

- level-0 エンコーダは MS-DOS 属性バイトを `0x20` (archive) に固定する。タイムスタンプは generic MS-DOS datetime を出力する。
