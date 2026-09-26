# LZSA

| 項目 | 内容 |
|------|------|
| 形式概要 | Emmanuel Marty らの LZSA。ストリーム形式 (`7b 9e` magic + traits + 64KiB フレーム列 + EOD フレーム) と、LZSA1 / LZSA2 という 2 種類のブロックフォーマットから構成される |
| 基準仕様 | `emmanuel-marty/lzsa` リポジトリの `StreamFormat.md` / `BlockFormat_LZSA1.md` / `BlockFormat_LZSA2.md` (v1.4.1)。参照実装は zlib license (`src/matchfinder.c` のみ CC0) |
| 実装 | `archive::compress::lzsa` (decode / decode_bounded / decode_lzsa1_block / decode_lzsa2_block / encode / encode_lzsa2)。pure-Rust 実装 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 3 バイトは `7b 9e` + traits byte (bits7-5 = version V、bits4-0 = reserved Z) | StreamFormat.md: header | ✅ | `lzsa1_stream_reference_vector` / `lzsa2_stream_reference_vector` (統合) |
| 2 | Z bits != 0 は拒否。V は 0 (LZSA1) / 1 (LZSA2) のみ、他は拒否 | StreamFormat.md: traits byte | ✅ | `rejects_bad_signature` |
| 3 | 各フレームは 3 バイトの圧縮ブロックサイズ DSZ (byte0-1 = bits0-15、byte2 bit0 = bit16) + DSZ バイトのブロックデータ | StreamFormat.md: frame | ✅ | `lzsa1_stream_reference_vector` (統合) |
| 4 | DSZ byte2 の bit7 は uncompressed frame フラグ。設定時、ブロックデータをそのまま出力にコピー | StreamFormat.md: uncompressed flag | ✅ | `decode_stream_uncompressed_frame` |
| 5 | DSZ byte2 の bits1-6 は reserved で非ゼロなら拒否 | StreamFormat.md | ✅ | `rejects_bad_signature` 経路で検証 |
| 6 | DSZ == 0 の 3 バイトが EOD フレーム (ストリーム終端) | StreamFormat.md: EOD | ✅ | 全ストリームベクタで検証 |
| 7 | フレームは最大 64KiB に展開。マッチオフセットは先行フレームの出力を参照可能 (ブロック間履歴) | StreamFormat.md | ✅ | `multi_frame_roundtrip` (統合、90000B) |

## LZSA1 ブロック

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 8 | コマンド列。各コマンドは token `<O\|LLL\|MMMM>` → 拡張リテラル長 → リテラル列 → オフセット下位 → [オフセット上位] → 拡張マッチ長 | BlockFormat_LZSA1.md | ✅ | `decode_l1_hand_built` |
| 9 | L = 0-6 直接、7 で拡張 byte: 0-248 → 7+v、249 → u16le、250 → 256+byte | BlockFormat_LZSA1.md: extra literal length | ✅ | `lzsa1_stream_reference_vector` (統合: 45 リテラル) |
| 10 | O bit 0 で 1 バイトオフセット (上位は 0xff → 距離 1-256)、1 で 2 バイト (距離 最大 64KiB)。オフセットは負値格納で dist = 0x10000 - stored | BlockFormat_LZSA1.md: match offset | ✅ | `lzsa1_raw_block_reference_vector` (統合: dist 45) |
| 11 | M = 0-14 で len = M+3。15 で拡張 byte: 0-237 → 18+v、238 → u16le (最終長)、239 → 256+byte | BlockFormat_LZSA1.md: extra match length / 参照 expand_block_v1.c | ✅ | `lzsa1_raw_block_reference_vector` (統合: len 8955) |
| 12 | ストリームブロックの最終コマンドはリテラルのみを含む (マッチなし)。ブロック境界はフレーム DSZ で判別 | BlockFormat_LZSA1.md | ✅ | `lzsa1_stream_reference_vector` (統合) |
| 13 | raw ブロックの最終コマンドは EOD マーカー: M=15 + オフセットバイト + 拡張 byte 238 + u16 0。EOD 以降にデータが残る場合は拒否 | BlockFormat_LZSA1.md: EOD detection | ✅ | `decode_l1_eod_raw`、`lzsa1_raw_block_reference_vector` (統合) |
| 14 | len-0 の EOD 条件はストリームモードでもブロック終端として受理 | 参照 expand_block_v1.c (`nMatchLen==0` → break) | ✅ | デコーダ実装 |

## LZSA2 ブロック

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | コマンド列。各コマンドは token `<XYZ\|LL\|MMM>` → 拡張リテラル長 → リテラル列 → オフセット (XYZ 形式) → 拡張マッチ長。min match = 2 | BlockFormat_LZSA2.md | ✅ | `lzsa2_stream_reference_vector` (統合) |
| 16 | ブロック全体で共有される nibble ストリーム: byte の hi nibble を先に返し lo nibble を保留、次の nibble 読み出しで返す。byte 読み出しは保留 nibble を消費しない | BlockFormat_LZSA2.md: Reading nibbles / 参照 shrink/expand 実装 (slot 書き戻し方式) | ✅ | `lzsa2_stream_reference_vector` (統合) |
| 17 | L = 0-2 直接、3 で拡張 nibble: 0-14 → 3+n、15 で byte: 238 → len 0、239 → u16le、その他 → 18+b | BlockFormat_LZSA2.md / 参照 expand_block_v2.c | ✅ | `lzsa2_stream_reference_vector` (統合: 32 リテラル) |
| 18 | オフセット形式: 00Z → 5bit (nibble+Zbit、dist 1-32)、01Z → 9bit (byte+Zbit、dist 1-512)、10Z → 13bit (nibble+Zbit+byte、dist 513-8704)、110 → 16bit、111 → rep-match (直前オフセット再利用) | BlockFormat_LZSA2.md: match offset | ✅ | `lzsa2_raw_block_reference_vector` (統合) |
| 19 | M = 0-6 で len = M+2。7 で拡張 nibble: 0-14 → 9+n、15 で byte: 232 → len 0 (EOD)、233 → u16le、その他 → 24+b | BlockFormat_LZSA2.md / 参照 expand_block_v2.c | ✅ | `decode_l2_eod_raw`、`lzsa2_raw_block_reference_vector` (統合: len 8955) |
| 20 | raw ブロックの最終コマンドは EOD: token の M=7 + 拡張 nibble 15 + byte 232 (オフセットは rep-match 等で読み飛ばし可) | BlockFormat_LZSA2.md: EOD detection / 参照 shrink_block_v2.c | ✅ | `decode_l2_eod_raw` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 21 | magic 欠損・3 バイト未満・フレームヘッダ/ブロック切り詰めの拒否 | StreamFormat.md | ✅ | `rejects_bad_signature`、`rejects_truncated` |
| 22 | オフセット 0 または出力済みバイト数超過のマッチは拒否 | LZ77 規約 | ✅ | `rejects_truncated` / デコーダガード |
| 23 | `decode_bounded` で出力上限を強制 (圧縮ブロック・verbatim フレーム双方) | crate contract | ✅ | `decode_bounded_enforces_limit` (統合) |
| 24 | 拡張長フィールドのマーカー byte (LZSA1: 238/239/249/250、LZSA2: 232/233/238/239) の曖昧な扱いを参照実装の読みに一致させる | 参照 expand_block_v1.c / expand_block_v2.c | ✅ | 参照ベクタで検証 |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 25 | `encode` は LZSA1 ストリーム、`encode_lzsa2` は LZSA2 ストリームを出力 (traits byte の V で選択) | StreamFormat.md | ✅ | `encode_roundtrips_and_redecodes` (統合) |
| 26 | フレームは 64KiB 出力単位で分割。マッチは先行フレームの履歴を参照可能 | StreamFormat.md | ✅ | `multi_frame_roundtrip` (統合) |
| 27 | 圧縮ブロックが入力以上に膨らむ場合、または 1 コマンドのリテラル長上限 (65535) を超えるリテラルランが発生した場合、verbatim フレームにフォールバック | StreamFormat.md: uncompressed flag | ✅ | 乱数入力の往復で検証 |
| 28 | ストリームブロックは必ずリテラルのみの最終コマンド (L=0 可) で閉じる。raw ブロックは EOD コマンドで閉じる | BlockFormat_LZSA1/2.md | ✅ | `lzsa_tool` 出力との比較 (ローカル検証) |
| 29 | LZSA2 エンコーダは距離に応じて 5bit (≤32) / 9bit (≤512) / 13bit (≤8704) / 16bit を選択し、直前距離と一致する場合は rep-match を出力 | BlockFormat_LZSA2.md | ✅ | `roundtrip_various` (tier テスト) |
| 30 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (LZSA1: 3B、LZSA2: 2B)。参照の optimal parse とのバイト一致は保証しない | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 31 | CLI は `lzsa` (v1) / `lzsa2` (v2) フォーマットで compress、ストリームの `7b 9e` magic で自動検出、raw ブロックは `--format` 必須 | crate CLI contract | ✅ | archive-cli 配線・detect テスト |

## 出典 / 検証メモ

- 参照実装 `emmanuel-marty/lzsa` は zlib license (`src/matchfinder.c` のみ CC0)。本実装は `StreamFormat.md` / `BlockFormat_LZSA1.md` / `BlockFormat_LZSA2.md` から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `TEXT_LZSA*` / `TEXT_RLZSA*` は参照 `lzsa` v1.4.1 (`-f1`/`-f2`、ストリームおよび `-r` raw) で生成した既知解答ベクタ (decode のみ検証)。
- ローカル検証として、本実装の `encode` / `encode_lzsa2` 出力を参照 `lzsa -d` で復号し一致を確認 (テキスト・混合・乱数入力)。非圧縮入力では verbatim フレームが選ばれることも一致確認。
- 仕様メモ: 拡張長フィールドの「特殊 byte」範囲は、仕様書にはエンコーダが出力する範囲のみ記載される。参照デコーダ (expand_block_v*.c) は byte 値を加算してオーバーフロー条件 (256/257) で分岐するため、仕様書未記載の byte 値 (LZSA1: 240-248,251-255 / LZSA2: 234-237,240-255 など) も非マーカー長として受理する。本実装は参照デコーダの挙動に合わせている。
- LZSA2 のオフセットは、仕様書では「負値格納 + 未使用ビット=1」のモデルで説明されるが、参照デコーダは `(stored ^ mask) + 1` で正の距離を直接得る。両モデルは等価であり、本実装は参照と同じ正距離モデルで書いている。
- LZSA1 の `lzsa -b` (backward) モード、辞書 (`-D`)、`lzsa` 独自の小ブロックストリーム API は対象外。
