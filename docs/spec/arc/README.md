# arc (SEA ARC)

| 項目 | 内容 |
|------|------|
| 基準仕様 | ARC file format description (System Enhancement Associates / wotsit "arc" entry、[fileformat.info mirror](https://www.fileformat.info/format/arc/corion.htm)、ローカルスナップショット: `docs/spec/sources/arc_format_corion.htm`)。併せて `Arcinfo` (SEA 自身の文書、hyc/arc 配布物に同梱) が ARC 5.xx directory format を記述する第二ソース |
| 参照実装 | newtua_dos (LGPL-3.0-or-later、method 5-7/0xa/0xb の移植元)、compcol (MIT、squeeze の適応元)、`compress::lzw` 共有コア (method 8/9 の LZW 層、de facto 源は ncompress `compress42.c` = public domain/Unlicense)。ARC 5.21 for Unix / nomarch は oracle のみ (実装参照ではない)、Debian `arc` 5.21q (fixture 生成)、arc/nomarch/unar/bsdtar/7z (oracle)。詳細: THIRD_PARTY_NOTICES arc 項・4a 節 |
| 形式概要 | 各 member は `0x1A` + method byte で開始、method 0 で終端。name は 13B NUL 埋めの flat 名 (directory 概念なし) |
| 実装範囲 | **method 1-9・0x0a・0x0b** の read、**method 1-9・0x0a・0x0b** の write。method 20-29・30-39 (ARC 6.0+ informational/control items) は header parse 後 skip。method 12-19・40+ の decode は intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 1 (obsolete unpacked) | ARC spec (Arcinfo bytes 26-29 注記) | ✅ | ✅ | method 2 と同型の 25B ヘッダだが orig-length フィールドなし (stored size が orig size を兼ねる)。CRC-16 検証。decode/encode ともに arc/nomarch/unar で展開確認済み |
| method 2 (stored) | ARC spec | ✅ | ✅ | CRC-16 検証 |
| method 3 (packed = RLE90) | de facto (virtualdub/compcol/XADMaster 一致) | ✅ | ✅ | `0x90` run marker、`0x90 0x00` escape。ヘッダは method 2 と同じ 29B、CRC-16 は非圧縮データ |
| method 4 (squeezed = RLE90 + static Huffman) | de facto (compcol/XADMaster 一致) | ✅ | ✅ | 静的 Huffman (numnodes u16 + len/value 対列) で pack 後 RLE90 列を符号化、`SPEOF` 終端。nomarch/arc で展開確認済み |
| method 5 (crunched, obsolete = quadratic-hash LZW) | de facto (XADMaster、arc/nomarch oracle 検証) | ✅ | ✅ | MSB-first 12-bit code、hash テーブル (quadratic variant) LZW、RLE90 段なし。decode/encode ともに arc/nomarch で展開確認済み |
| method 6 (crunched = quadratic-hash LZW + RLE90) | de facto (XADMaster、arc/nomarch oracle 検証) | ✅ | ✅ | method 5 と同じ LZW、出力を RLE90 展開。decode/encode ともに arc/nomarch で展開確認済み |
| method 7 (crunched fast = multiplicative-hash LZW + RLE90) | de facto (XADMaster/arc 一致) | ✅ | ✅ | hash のみ multiplicative に差し替え。decode/encode ともに arc で展開確認済み (nomarch は method 7 非対応) |
| method 8 (crunched = dynamic LZW + RLE90) | de facto (compcol + `compress::lzw`/compress42.c、arc/nomarch oracle 検証) | ✅ | ✅ | 先頭 1B が maxbits (実環境は 12)、compress 式 9→12bit 可変幅 LZW + block mode (0x100 reset) の出力を RLE90 展開。Debian `arc` 生成 fixture で decode 確認済み |
| method 9 (squashed = dynamic LZW、RLE なし) | de facto (newtua_dos、`compress::lzw`/compress42.c、nomarch oracle 検証) | ✅ | ✅ | compress 式 9→13bit 可変幅 LZW + block mode、RLE90 段なし。compcol の「固定 13bit」記述は誤り (newtua_dos 側が nomarch と一致)。Debian `arc` 生成 fixture で decode 確認済み |
| method 0x0a (crushed = adaptive LZW + RLE90) | de facto (XADMaster port / unar 一致) | ✅ | ✅ | LSB-first、literal-bit モード切替 + usage ベース置換の adaptive LZW、RLE90 段あり。decode/encode ともに unar・newtua (XADMaster port、リポジトリ外の相互検証) で展開確認済み (arc/nomarch は非対応) |
| method 0x0b (distilled = LZSS + header Huffman) | de facto (XADMaster port) | ✅ | ✅ | 8KiB LZSS + ヘッダ内シリアライズ Huffman + 固定 offset prefix 表。現行 oracle (arc/nomarch/unar) は 0x0b を decode しないため、decode は XADMaster port 一致ベクタ、encode は自 decoder roundtrip + newtua decoder 相互検証 (リポジトリ外) のみ |
| method 20-29 (informational items)・30-39 (control items) | ARC spec (SEA technical memo、ARC 6.0) | ✅ | ❌ | 通常 member と同一ヘッダで parse 後 payload を `length` バイト skip (`skips_info_control_items`)。file ではないため entry として surface しない設計 (sub-type payload は解釈しない)。encode の info/control item emit は対象外 |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | member marker `0x1A` + method byte、method 0 で終端 | ARC spec | ✅ | `roundtrip` |
| 2 | filename: 13 バイト NUL 埋め。`/`・`\` を含む場合は reject | ARC spec | ✅ | `rejects_bad_name`, `test_arc_rejects_bad_name` |
| 3 | method 1: `[name][size u32le][date u16][time u16][crc16 u16][data]` — orig-length (bytes 26-29) のみ欠落、ヘッダ 25B | ARC spec (Arcinfo bytes 26-29 注記) | ✅ | `method1_member`, `test_arc_method1_member` |
| 4 | method 2 以上: `[name][length u32le][date u16][time u16][crc16 u16][size u32le][data]` — bytes 16-19 が stored (compressed) size、bytes 26-29 が original (uncompressed) size | ARC spec (Arcinfo bytes 16-19/26-29) | ✅ | `roundtrip`、Debian `arc` 生成 fixture `fix8.arc`/`fix9.arc` で確認 |
| 5 | bounds 検査 (truncated header/marker/data → エラー) | crate エラー規約 | ✅ | `test_arc_rejects_truncated`、`truncated_prefix_invariant` (任意の切断位置でエラーまたは正当なエントリ接頭辞) |
| 6 | filename は UTF-8 必須 | crate エラー規約 | ✅ | `rejects_bad_name`, `test_arc_rejects_bad_name` |

### メソッド / データ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | method 1/2: data は生バイト列、stored size == member size 必須 | ARC spec | ✅ | `roundtrip`, `method1_member` |
| 8 | method 3 (packed): RLE90 展開後の長さが declared original size と一致必須 | de facto | ✅ | `method3_member`, `method3_roundtrip`, `method3_rejects_malformed_rle` |
| 9 | method 4 (squeezed): numnodes 表の検証 + LSB-first Huffman 復号 + RLE90 展開 + SPEOF/size 一致 | de facto | ✅ | `squeeze::tests` (roundtrip/empty/bad-table/truncated)、`test_arc_compressed_encode_decode_roundtrip`、nomarch/arc oracle 展開 |
| 10 | method 5/6 (crunched quadratic)・7 (multiplicative): MSB-first 12-bit hash-LZW 復号、6/7 は RLE90 段、size 一致必須 | de facto | ✅ | `crunch::tests` (quadratic/multiplicative ベクタ、bound)、`test_arc_method5_6_7_decode`、arc/nomarch oracle |
| 11 | method 8 (crunched): maxbits byte + compress 式 LZW (9→12bit、block mode) → RLE90 展開 | de facto | ✅ | `test_arc_decode_crunched_fixture` (Debian `arc` 生成)、nomarch/arc oracle 展開 |
| 12 | method 9 (squashed): compress 式 LZW (9→13bit、block mode)、RLE 段なし、size 一致必須 | de facto | ✅ | `test_arc_decode_squashed_fixture` (Debian `arc` 生成)、nomarch/arc oracle 展開 |
| 13 | method 0x0a (crushed): LSB-first adaptive LZW (literal-bit 切替・usage 置換) → RLE90 展開、size 一致必須 | de facto | ✅ | `crush::tests` (ベクタ、EOF/truncated)、`test_arc_method0a_decode`、unar oracle |
| 14 | method 0x0b (distilled): numnodes/codelength 検証 + LSB-first Huffman walk + 8KiB LZSS + 固定 offset 表、size 一致必須 | de facto | ✅ | `distill::tests` (literal/match/malformed)、`test_arc_method0b_decode` (XADMaster 一致確認ベクタ) |
| 15 | method 12-19 (unknown)・40+ (reserved) は `Error::Unsupported` | crate scope | ✅ | `rejects_compressed_method`, `test_arc_rejects_compressed_method` |
| 15a | method 20-29 (informational items)・30-39 (control items): 通常 member と同一ヘッダを parse して payload `length` バイトを skip、entry は生成しない (SEA memo: orig file size・name は無視可能と規定) | ARC spec (SEA technical memo、ARC 6.0) | ✅ | `skips_info_control_items`, `rejects_truncated_info_item`, `test_arc_skips_info_control_items` |
| 16 | method 1 以上の CRC-16 (CRC-16/ARC、poly 0x8005 reflected) を検証、不一致は reject | ARC spec | ✅ | `rejects_bad_crc`, `method1_rejects_bad_crc`, `method3_rejects_bad_crc`, `test_arc_method1_rejects_bad_crc` |
| 17 | method 1 member は orig-length を持たず `size` は stored size と同値。`crc16`/`date`/`time` は通常通り検証・返却される | ARC spec (Arcinfo bytes 26-29 注記) | ✅ | `method1_member`, `method1_rejects_bad_crc` |
| 17a | method 3/4 の declared original size が確保できないときは `InvalidData` で拒否する | crate | ✅ | `rle90_rejects_unreservable_size`, `squeeze_rejects_unreservable_size` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 18 | `ArcEncoder::add_file` / `encode`: method-2 member + name 1-12B・NUL/パス区切りなし | ARC spec | ✅ | `roundtrip`, `rejects_long_name` |
| 19 | 終端 `0x1A 0x00` を付与 | ARC spec | ✅ | 往復テスト (decode は EOF 終了も許容 — lax) |
| 20 | method-1 member の emit: `add_file_with_method(name, data, date, time, 1)` — `[0x1A][1][name 13B][size u32le][date u16][time u16][crc16 u16][data]` (orig-length なし) | ARC spec (Arcinfo bytes 26-29 注記) | ✅ | `method1_roundtrip`, `method1_header_layout`, `rejects_unsupported_encode_method`, `test_arc_method1_encode_decode_roundtrip`, `test_arc_method1_header_layout`, `test_arc_rejects_unsupported_encode_method`、arc/nomarch/unar oracle 展開 (`test_arc_encode_extracted_by_oracle`) |
| 21 | method 3-9・0x0a・0x0b の emit: `add_file_with_method` で packed/squeezed/crunched (3 種) /squashed/crushed/distilled member を生成 | de facto | ✅ | `test_arc_compressed_encode_decode_roundtrip`、`test_arc_method5_6_7_edge_roundtrip`、`test_arc_method0a_encode_roundtrip`、`test_arc_method0b_encode_roundtrip`、`crunch::tests::encode_*`・`crush::tests::encode_*`・`distill::tests::encode_*`、oracle 展開 (`test_arc_encode_extracted_by_oracle`: 1/4/8/9→arc+nomarch+unar、5/6→arc+nomarch、7→arc、0x0a→unar、0x0b は対応 oracle なし) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | `0x1A` + method byte (1-9, 0x0a, 0x0b, 20-39) で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_arc` (同上: spawn 統合テスト基盤は未整備)。`0x1A` 先頭は HYP/ZOO と衝突し得るため method byte 範囲で絞る |
| 23 | fuzz harness `arc` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Arc` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 24 | method 12-19・40+ (ARC 6.0+ の unknown/reserved items) の decode は非対応 | ❌ | `Error::Unsupported` を返す (公開 wire format なし) |
| 25 | method 5-9・0x0a・0x0b の圧縮ワイヤ形式は書面仕様なし (de facto) | — | XADMaster port (newtua_dos、LGPL) / nomarch / hyc-arc (GPL oracle) / compcol (MIT) の挙動一致で妥当性確認。method 9 の LZW 可変幅は compcol 記述と異なり nomarch/newtua 側 (9→13bit 可変) を採用。encode 側は method 5-7 を arc/nomarch oracle、0x0a を unar/newtua で展開確認済み。0x0b は利用可能 oracle が decode を持たないため、decode は XADMaster port 一致ベクタ、encode は newtua decoder 相互検証 (リポジトリ外) のみ |
| 26 | self-unpacking (SFX) archive の先頭最大 3B prefix は非対応 | — | Arcinfo SELF-UNPACKING 節。decode は先頭 `0x1A` 必須、detect も同様 |
| 27 | method 20-29/30-39 の sub-record 構造 (`u16 len` + `u8 subtype` + data) は解釈しない | — | corion SEA memo 節。payload は長さ分 skip のみ (#15a) |
| 28 | date/time は MS-DOS bit layout (Arcinfo bytes 20-23、corion Table 0009) の raw u16 として保持し意味解釈しない (sec/2 精度のため奇数秒は表現不可) | — | date 全 0 = 日付なし、の意味付けも呼び出し側に委ねる |
| 29 | Spark/Archimedes 拡張 (method|0x80、dir entry 0x1e/0x1f) は非対応 | — | XADMaster/newtua が実装する拡張。基準仕様 (corion) の範囲外 |
