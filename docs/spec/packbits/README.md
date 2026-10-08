# PackBits

| 項目 | 内容 |
|------|------|
| 形式概要 | flag-counter バイトを先頭に持つパケットの列からなる RLE codec。`0..=127` は続く N+1 バイトのリテラル、`129..=255` (signed `-127..=-1`) は続く 1 バイトを `1-N` 回反復、`128` (`-128`) は予約済み no-op |
| 基準仕様 | [Apple Technical Note TN1023 "Understanding PackBits"](https://developer.apple.com/library/mac/technotes/tn1023/_index.html) (ローカルスナップショット: `docs/spec/sources/apple_tn1023_packbits.html`)、[TIFF Revision 6.0](https://download.osgeo.org/libtiff/doc/TIFF6.pdf) Section 9 "PackBits Compression" (スナップショット: `docs/spec/sources/tiff6.pdf` — Standard RC4-40 (空パスワード) + LZWDecode フィルタで §9 を抽出し直接検証済み) |
| 参照実装 | なし (書面仕様のみに基づいて実装) |
| 実装 | `archive::compress::packbits` (encode / decode)。`packbits` feature 配下 |

## パケット構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | flag-counter `0..=127`: 続く N+1 バイトをリテラルとして複写 | TN1023 "Specifying the Flag-counter Byte"、TIFF6 §9 | ✅ | `literal_packet`、`decode_known_vector` |
| 2 | flag-counter `129..=255` (signed `-127..=-1`): 続く 1 バイトを `257-N` (= `1-signed`) 回反復 | 同上 | ✅ | `repeat_packet`、`tn1023_worked_example` |
| 3 | flag-counter `128` (`-128`) は no-op として読み飛ばす | TN1023 "Using PackBits" 警告 (UnpackBits は `$80` を skip)、TIFF6 §9 | ✅ | `nop_flag_ignored` |
| 4 | リテラルパケットが入力末尾で途切れる場合は `UnexpectedEof` | バリデーション | ✅ | `truncated_rejected` |
| 5 | 反復パケットが入力末尾で途切れる場合は `UnexpectedEof` | バリデーション | ✅ | `truncated_rejected` |
| 6 | 入力末尾までパケット列を消費 (長さ引数を取らない streaming ではなく、全入力を decode する契約) | TN1023 "no way to know when you have reached the end" — コンテナ側が長さを持つ前提 | ✅ | 全 decode テスト |

## encode 方針

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 7 | 3 バイト以上の連続同一バイトのみ反復パケット化 (1〜2 バイトの run はリテラルに含める) | TN1023 "PackBits packs the data only when there are three or more consecutive bytes" | ✅ | `two_byte_run_stays_literal`、`tn1023_worked_example`。TIFF §9 は 2-byte run の replicate 化を推奨するが、本実装は TN1023 準拠で常にリテラル (decode 上は等価、byte-exact 差) |
| 8 | 1 パケットあたりの最大長はリテラル・反復ともに 128 バイト | TN1023 / TIFF6 §9 (flag-counter の値域) | ✅ | `repeat_packet` (128→`0x81`)、`literal_packet`、`literal_packet_splits_at_128` |
| 9 | 129 バイト超の run は複数パケットに分割 (128+残り、残り 1〜2 バイトはリテラルパケットとして出力) | 実装方針 | ✅ | `repeat_packet` |
| 10 | エンコーダは flag-counter `0x80` (`-128`) を生成しない | TN1023 "PackBits never generates the value -128" | ✅ | `worst_case_bound`、`literal_packet_splits_at_128` (flag 位置の 0x80 非出現を assert) |
| 11 | TN1023 の公式作例 (`AA AA AA 80 00 2A …`) をバイト一致で再現 | TN1023 worked example | ✅ | `tn1023_worked_example` (KAT) |
| 12 | 最悪出力サイズ ≦ `srcBytes + (srcBytes+126)/127` | TN1023 "worst case" 公式 | ✅ | `worst_case_bound` |

## 意図的な scope 制約

| # | 項目 | 状態 | 備考 |
|---|------|------|------|
| 13 | 行単位フレーミング (PICT PixData の `byteCount` 前置き / TIFF §9 の "Pack each row separately" + 行長 `(ImageWidth+7)/8`) | ❌ intentional scope | 画像フォーマット固有の行単位セマンティクスはコンテナ層の領域。本 codec は純粋なパケット列のみ |
| 14 | 一部コンテナが使う `0x80` = end-of-stream 解釈 | ❌ intentional scope | 汎用 codec としては TN1023/TIFF 準拠の no-op 扱いに固定。end マーカー解釈はコンテナ側の責務 |
| 15 | 展開後サイズの事前検証 | ❌ intentional scope | TN1023 も「UnPackBits は展開長を必要とする」と明記。呼び出し側 (コンテナ) が既知長を与える設計 |

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 12 |
| ⚠️ 部分対応  | 0 |
| ❌ 未対応  | 3 (いずれも intentional scope) |
| **合計** | **15** |
