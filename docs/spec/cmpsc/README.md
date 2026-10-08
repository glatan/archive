# CMPSC (basic method)

| 項目 | 内容 |
|------|------|
| 形式概要 | IBM CMPSC (Compression Call) 命令の基本方式。静的辞書を使う LZ78 系で、圧縮出力は固定長 index symbol (9-13bit、辞書エントリ数 512/1K/2K/4K/8K に対応) の MSB-first 連結 |
| 基準仕様 | [z/Architecture Principles of Operation (SA22-7832-12)](https://publibfp.boulder.ibm.com/epubs/pdf/a227832c.pdf) Chapter 7 COMPRESSION CALL + Appendix D "Compression Call Facility"。辞書フォーマット自体は IBM [ESA/390 Data Compression (SA22-7208)](https://www.ibm.com/resources/publications/OutputPubsDetails?PubID=SA22720801) (BKMGR softcopy) が正本。コンテナは PKWARE [APPNOTE.TXT](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) §5.17 (method 16)。ローカルスナップショット: `docs/spec/sources/sa22-7832-12.pdf` |
| 参照実装 | なし (実装は IBM POP/SA22-7208 の書面記述に基づく)。SDL-Hercules-390/hyperion (QPL) は過去にビットレイアウト解釈の確認に一度参照したのみで、現行コードの実装ベースではない (全クレームは POP/SA22-7208 に帰属)。詳細: THIRD_PARTY_NOTICES cmpsc 項 |
| 実装 | `archive::compress::cmpsc` (expand / compress / decode / encode)。pure-Rust 実装 |

## スコープ

基本方式のみ。以下は **intentional scope** 外:

- format-1 sibling descriptor (展開辞書に第 2 doubleword を持つ形式)
- symbol translation / order preservation
- entropy encoding (CMPSC-enhancement facility、z14+)
- 圧縮データ operand の先頭 bit offset (GR1 CBN) — 実装は常に bit0 から parse (byte コンテナ codec としての scope)
- GR0 bit46 ZP (zero-padding、CMPSC-enhancement)
- method-16 の deflate 圧縮辞書フラグ (0x40) は拒否

## Index symbol ストリーム

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | index symbol は辞書エントリ数を示す冪乗ビット長 (512=9bit … 8K=13bit)。範囲外の symbol size は拒否 | POP App.D Compression Process | ✅ | `cmpsc_rejects_malformed` (統合) |
| 2 | symbol は圧縮データ operand に MSB-first で詰め込まれる。末尾の端数ビット (symbol 未満) は無視 | POP Chapter 7 / operand model | ✅ | `cmpsc_method16_explicit_vector` (統合) |
| 3 | index は辞書エントリ数未満でなければならない。辞書長が 8 の倍数でない・アルファベット (256) 未満・上限超過は拒否 | POP App.D Dictionary Formats | ✅ | `cmpsc_rejects_malformed` (統合) / `rejects_bad_input` |

## 展開辞書 (expansion)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 4 | エントリは 8 バイト。bits0-2 = PSL。PSL=0 は unpreceded entry: bits3-4 = 0 (非ゼロは data exception として reject)、bits5-7 = CSL (1-7)、bytes1-7 に EC 列 | POP App.D Expansion Dictionary | ✅ | `cmpsc_expand_alphabet_and_chains` (統合) / `expand_rejects_bad_unpreceded_entry` |
| 5 | PSL>0 は preceded entry: bits3-15 = PPTR (predecessor index)、bytes2-6 に EC 列 (最大 5)、byte7 = OFST。PSL 6/7 は model-dependent (実装は 5 として扱う — architecturally permitted) | 同上 | ✅ | 同上 (258 "ABC" = PPTR 256 + EC 'C') |
| 6 | 展開は PPTR chain を遡り unpreceded entry まで再帰し、ルートから順に EC を出力 (OFST 方式と等価、dict が整合的な場合。実装は PPTR chain 方式) | 同上 / model-dependent note | ✅ | `expand_preceded_chain` |
| 7 | predecessor cycle・index 範囲外は拒否。出力は `max_output` で制限 | crate contract | ✅ | `cmpsc_rejects_malformed` (統合) |
| 21 | index symbol 0-255 は展開辞書を参照せず、値のバイトをそのまま出力 (alphabet entry の内容が不正でも影響しない) | POP App.D Expansion Process | ✅ | `expand_alphabet_bypasses_dictionary` |
| 22 | unpreceded entry の bits3-4 非ゼロ / CSL=0 は拒否 (POP: data exception 許容の厳格側を選択) | POP App.D Expansion Dictionary | ✅ | `expand_rejects_bad_unpreceded_entry` |

## 圧縮辞書 (compression、format-0)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 8 | alphabet entry (0-255) は入力の 1 バイトで直接選択。child 探索で最後に一致したエントリの index を出力 | POP App.D Compression Process | ✅ | `compress_then_expand` |
| 9 | CCT=0 (子なし): ACT = bits8-10、EC は byte 3 以降 | POP App.D Compression Dictionary | ✅ | リーフ子で検証 |
| 10 | CCT=1: X = bit3 (examine)、ACT = bits8-10、CPTR = bits11-23、EC + 1 個の CC。X=0 の child は entry を fetch せず即選択して match 終了、X=1 で EC/子 entry を検査して descend | 同上 | ✅ |  (X=0 で 268 へ descend せず 257+'Y'、X=1 で "ABC"→258) |
| 11 | CCT≥2: XXXXX = bits3-7、YY = bits8-9、ACT = bit10 (0/1 のみ)、CPTR = bits11-23、[EC] + CC 列。CCT = 5-ACT+1 で sibling descriptor が最後の子の後に続く | 同上 | ✅ | 'S' エントリ (CCT=6, 5 子 + SD) で検証 |
| 12 | format-0 sibling descriptor: SCT = bits0-2、examine bits3-7、SC = bytes1-7。POP: "SCT (0-7); zero is treated as 7 and indicates another SD follows 7th sibling" — 継続印は SCT=0 のみ。SD 自身も index を占め、指定する子は SD index+1 以降に連続 | 同上 / Format-0 Sibling Descriptor | ✅ | 修正済み — POP 準拠で `raw == 0` のみを「7 sibling + 継続」と判定 (SCT=7 は継続なし)。`cmpsc_compress_expand_roundtrip`。SD の examine bits (及び YY) は未解釈で常時 examine として扱う (intentional) |
| 13 | 子 index = CPTR + ordinal で連続配置。matching は unordered comparison: 子/兄弟を左から走査、先行子の EC mismatch 後も残りの子を走査継続 (architected model-permitted 動作) | 同上 / Child and Sibling Characters | ✅ | 上記テストで検証 |
| 14 | 出力 symbol = 最後に一致したエントリの index。マッチ失敗時は現在の親を出力 | POP App.D | ✅ | `compress_matches_expected_symbols` |

## method-16 コンテナ (PKWARE APPNOTE §5.17)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | `[version=1][flags/symsize][u32 dict len][expansion dict][CMPSC data]`。flags 上位 4bit、symsize 下位 4bit (9-13) | APPNOTE 5.17 | ✅ | `cmpsc_method16_roundtrip` (統合) |
| 16 | flag 0x80 (expansion dictionary 存在) 必須。0x40 (deflate 辞書) は unsupported として拒否、0x20/0x10 reserved 拒否 | APPNOTE 5.17 | ✅ | `cmpsc_rejects_malformed` (統合) |
| 17 | DictionaryLen は u32 BE でバイト長。辞書が入力を超える場合は拒否 | APPNOTE 5.17 / 実装選択 (z/OS 系フィールドは BE) | ✅ | 同上 |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 18 | `compress` は caller 提供の圧縮辞書 (format-0 SD のみ) で unordered comparison を行う。辞書生成 (キャリブレーション) は scope 外 | crate-local | ✅ | `cmpsc_compress_expand_roundtrip` (統合) |
| 19 | `encode` は alphabet-only 辞書の method-16 ストリームを出力 (1 byte = 1 index symbol、非圧縮)。LZXD uncompressed encoder と同じく往復・相互運用検証用 (intentional scope) | crate-local | ✅ | `cmpsc_method16_roundtrip` (統合) |
| 20 | CLI `cmpsc` format は method-16 コンテナのみ扱う。生の index symbol 列は辞書・symsize が out-of-band なので自動検出しない | crate-local | ✅ | `archive compress cmpsc` / `extract --format cmpsc` |

## ライセンス / 出自

- 実装は POP Appendix D の辞書フォーマット記述と APPNOTE §5.17 に基づく pure-Rust 新規実装。
- Hercules (SDL-Hercules-390/hyperion、QPL) はビットレイアウトの**解釈確認**に過去一度参照したのみ (コード複製なし、成果物への組み込みなし、実装ベースではない)。同梱の `readme/README.CMPSC.md` はエミュレーションコードとは別の文書。
- 既知解答はテスト内で POP 記述から構築した辞書と手計算 symbol 列で検証 (外部生成ベクタは未入手: 実機/Hercules が必要なため)。
