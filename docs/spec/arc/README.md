# arc (SEA ARC)

| 項目 | 内容 |
|------|------|
| 基準仕様 | ARC file format description (System Enhancement Associates / wotsit "arc" entry、[fileformat.info mirror](https://www.fileformat.info/format/arc/corion.htm)、ローカルスナップショット: `docs/spec/sources/arc_format_corion.htm`)。併せて [hyc/arc](https://github.com/hyc/arc) 同梱の `Arcinfo` が ARC 5.xx directory format を記述する第二ソース |
| 形式概要 | 各 member は `0x1A` + method byte で開始、method 0 で終端。name は 13B NUL 埋めの flat 名 (directory 概念なし) |
| 実装範囲 | **method 1-9・0x0a・0x0b** の read。write は method 1-4・8・9。method 5-7・0x0a・0x0b の encode と method 0x0c 以降は intentional scope 外 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| method 1 (obsolete unpacked) | ARC spec | ✅ | ✅ | CRC-16 フィールドなし |
| method 2 (stored) | ARC spec | ✅ | ✅ | CRC-16 検証 |
| method 3 (packed = RLE90) | de facto (virtualdub/compcol/XADMaster 一致) | ✅ | ✅ | `0x90` run marker、`0x90 0x00` escape。ヘッダは method 2 と同じ 29B、CRC-16 は非圧縮データ |
| method 4 (squeezed = RLE90 + static Huffman) | de facto (compcol/nomarch/XADMaster 一致) | ✅ | ✅ | 静的 Huffman (numnodes u16 + len/value 対列) で pack 後 RLE90 列を符号化、`SPEOF` 終端。nomarch/arc で展開確認済み |
| method 5 (crunched, obsolete = quadratic-hash LZW) | de facto (XADMaster/nomarch/arc 一致) | ✅ | ❌ | MSB-first 12-bit code、hash テーブル (quadratic variant) LZW、RLE90 段なし。arc/nomarch で展開確認済み |
| method 6 (crunched = quadratic-hash LZW + RLE90) | de facto (XADMaster/nomarch/arc 一致) | ✅ | ❌ | method 5 と同じ LZW、出力を RLE90 展開。arc/nomarch で展開確認済み |
| method 7 (crunched fast = multiplicative-hash LZW + RLE90) | de facto (XADMaster/arc 一致) | ✅ | ❌ | hash のみ multiplicative に差し替え。arc で展開確認済み (nomarch は method 7 非対応) |
| method 8 (crunched = dynamic LZW + RLE90) | de facto (compcol/nomarch/hyc-arc 一致) | ✅ | ✅ | 先頭 1B が maxbits (実環境は 12)、compress 式 9→12bit 可変幅 LZW + block mode (0x100 reset) の出力を RLE90 展開。Debian `arc` 生成 fixture で decode 確認済み |
| method 9 (squashed = dynamic LZW、RLE なし) | de facto (nomarch/newtua_dos 一致) | ✅ | ✅ | compress 式 9→13bit 可変幅 LZW + block mode、RLE90 段なし。compcol の「固定 13bit」記述は誤り (nomarch/newtua が一致)。Debian `arc` 生成 fixture で decode 確認済み |
| method 0x0a (crushed = adaptive LZW + RLE90) | de facto (XADMaster port / unar 一致) | ✅ | ❌ | LSB-first、literal-bit モード切替 + usage ベース置換の adaptive LZW、RLE90 段あり。unar で展開確認済み (arc/nomarch は非対応) |
| method 0x0b (distilled = LZSS + header Huffman) | de facto (XADMaster port) | ✅ | ❌ | 8KiB LZSS + ヘッダ内シリアライズ Huffman + 固定 offset prefix 表。現行 oracle (arc/nomarch/unar) は 0x0b を decode しないため、XADMaster port と byte 一致を確認した手組みベクタで検証 |

### ヘッダ構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 1 | member marker `0x1A` + method byte、method 0 で終端 | ARC spec | ✅ | `roundtrip` |
| 2 | filename: 13 バイト NUL 埋め。`/`・`\` を含む場合は reject | ARC spec | ✅ | `parse_name` |
| 3 | method 1: `[name][size u32le][data]` — date/time/CRC/orig-length フィールドなし | ARC spec | ✅ | `method1_member`, `test_arc_method1_member` |
| 4 | method 2 以上: `[name][length u32le][date u16][time u16][crc16 u16][size u32le][data]` — bytes 16-19 が stored (compressed) size、bytes 26-29 が original (uncompressed) size | ARC spec (Arcinfo bytes 16-19/26-29) | ✅ | `roundtrip`、Debian `arc` 生成 fixture `fix8.arc`/`fix9.arc` で確認 |
| 5 | bounds 検査 (truncated header/marker/data → エラー) | crate エラー規約 | ✅ | `test_arc_rejects_truncated` |
| 6 | filename は UTF-8 必須 | crate エラー規約 | ✅ | `parse_name` |

### メソッド / データ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 7 | method 1/2: data は生バイト列、stored size == member size 必須 | ARC spec | ✅ | `roundtrip`, `method1_member` |
| 8 | method 3 (packed): RLE90 展開後の長さが declared original size と一致必須 | de facto | ✅ | `method3_member`, `method3_roundtrip`, `method3_rejects_malformed_rle` |
| 9 | method 4 (squeezed): numnodes 表の検証 + LSB-first Huffman 復号 + RLE90 展開 + SPEOF/size 一致 | de facto | ✅ | `squeeze::tests` (roundtrip/empty/bad-table/truncated)、`test_arc_method4_8_9_encode_decode_roundtrip`、nomarch/arc oracle 展開 |
| 10 | method 5/6 (crunched quadratic)・7 (multiplicative): MSB-first 12-bit hash-LZW 復号、6/7 は RLE90 段、size 一致必須 | de facto | ✅ | `crunch::tests` (quadratic/multiplicative ベクタ、bound)、`test_arc_method5_6_7_decode`、arc/nomarch oracle |
| 11 | method 8 (crunched): maxbits byte + compress 式 LZW (9→12bit、block mode) → RLE90 展開 | de facto | ✅ | `test_arc_decode_crunched_fixture` (Debian `arc` 生成)、nomarch/arc oracle 展開 |
| 12 | method 9 (squashed): compress 式 LZW (9→13bit、block mode)、RLE 段なし、size 一致必須 | de facto | ✅ | `test_arc_decode_squashed_fixture` (Debian `arc` 生成)、nomarch/arc oracle 展開 |
| 13 | method 0x0a (crushed): LSB-first adaptive LZW (literal-bit 切替・usage 置換) → RLE90 展開、size 一致必須 | de facto | ✅ | `crush::tests` (ベクタ、EOF/truncated)、`test_arc_method0a_decode`、unar oracle |
| 14 | method 0x0b (distilled): numnodes/codelength 検証 + LSB-first Huffman walk + 8KiB LZSS + 固定 offset 表、size 一致必須 | de facto | ✅ | `distill::tests` (literal/match/malformed)、`test_arc_method0b_decode` (XADMaster 一致確認ベクタ) |
| 15 | method 0x0c 以降は `Error::Unsupported` | crate scope | ✅ | `rejects_compressed_method`, `test_arc_rejects_compressed_method` |
| 16 | method 2 以上の CRC-16 (CRC-16/ARC、poly 0x8005 reflected) を検証、不一致は reject | ARC spec | ✅ | `rejects_bad_crc`, `method3_rejects_bad_crc` |
| 17 | method 1 member は CRC フィールドを持たないため `crc16: None` で返す | ARC spec | ✅ | `method1_member` |

### encode

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 18 | `ArcEncoder::add_file` / `encode`: method-2 member + name 1-12B・NUL/パス区切りなし | ARC spec | ✅ | `roundtrip`, `rejects_long_name` |
| 19 | 終端 `0x1A 0x00` を付与 | ARC spec | ✅ | 往復テスト |
| 20 | method-1 member の emit: `add_file_with_method(name, data, date, time, 1)` — `[0x1A][1][name 13B][size u32le][data]` (CRC/date/time/length なし) | ARC spec | ✅ | `method1_roundtrip`, `method1_header_layout`, `rejects_unsupported_encode_method`, `test_arc_method1_encode_decode_roundtrip`, `test_arc_method1_header_layout`, `test_arc_rejects_unsupported_encode_method` |
| 21 | method 3/4/8/9 の emit: `add_file_with_method` で packed/squeezed/crunched/squashed member を生成 | de facto | ✅ | `test_arc_method4_8_9_encode_decode_roundtrip`、nomarch/arc/unar oracle 展開 (`test_arc_encode_extracted_by_oracle`) |

### CLI / fuzz 連携

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|-----------|----------------|
| 22 | `0x1A` + method byte (1-9, 0x0a, 0x0b) で自動検出、`list`/`extract`/`test`/`inspect`/`pack` に対応 | CLI 規約 | ✅ | `detect_arc` (同上: spawn 統合テスト基盤は未整備) |
| 23 | fuzz harness `arc` で encode→decode 往復 | fuzz 規約 | ✅ | `Algorithm::Arc` |

### 既知制約 (intentional scope)

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 24 | method 5-7・0x0a・0x0b の encode は非対応 | ❌ | `Error::Unsupported` を返す。decode のみ scope (現行 `arc` 5.21q はこれらの method を生成しないため需要も限定的) |
| 25 | method 0x0c 以降 (PKPAK/PAK 系・gzip 埋め込み等) の decode は非対応 | ❌ | `Error::Unsupported` を返す |
| 26 | method 5-9・0x0a・0x0b の圧縮ワイヤ形式は書面仕様なし (de facto) | — | XADMaster port (newtua_dos、LGPL) / nomarch / hyc-arc (GPL oracle) / compcol (MIT) の挙動一致で妥当性確認。method 9 の LZW 可変幅は compcol 記述と異なり nomarch/newtua 側 (9→13bit 可変) を採用。0x0b は利用可能 oracle が decode を持たないため XADMaster port との byte 一致で検証 |
