# LZSA

| 項目 | 内容 |
|------|------|
| 形式概要 | Emmanuel Marty らの LZSA。ストリーム形式 (`7b 9e` magic + traits + 64KiB フレーム列 + EOD フレーム) と、LZSA1 / LZSA2 という 2 種類のブロックフォーマットから構成される |
| 基準仕様 | [`emmanuel-marty/lzsa`](https://github.com/emmanuel-marty/lzsa) リポジトリの [`StreamFormat.md`](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/StreamFormat.md) / [`BlockFormat_LZSA1.md`](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA1.md) / [`BlockFormat_LZSA2.md`](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA2.md) (v1.4.1、ローカルスナップショット: `docs/spec/sources/lzsa_*_1.4.1.md`)。参照実装は zlib license (`src/matchfinder.c` のみ CC0) |
| 参照実装 | upstream `lzsa` (Emmanuel Marty 他、zlib license / `src/matchfinder.c` は CC0、動作参照 + fixture 生成: `tests/integration/lzsa.rs` の known-answer ベクターは `lzsa` v1.4.1 出力)。性能比較 (`docs/bench/`) でも使用。詳細: THIRD_PARTY_NOTICES LZSA 項 |
| 実装 | `archive::compress::lzsa` (decode / decode_bounded / decode_lzsa1_block / decode_lzsa2_block / decode_with_prefix / decode_lzsa1_block_with_prefix / decode_lzsa2_block_with_prefix / decode_lzsa1_block_backwards / decode_lzsa1_block_backwards_with_prefix / decode_lzsa2_block_backwards / decode_lzsa2_block_backwards_with_prefix / encode / encode_lzsa2 / encode_with_prefix / encode_lzsa2_with_prefix / encode_lzsa1_block / encode_lzsa1_block_with_prefix / encode_lzsa2_block / encode_lzsa2_block_with_prefix / encode_lzsa1_block_backwards / encode_lzsa1_block_backwards_with_prefix / encode_lzsa2_block_backwards / encode_lzsa2_block_backwards_with_prefix)。pure-Rust 実装 |

## 対応バリアント・仕様版

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| stream コンテナ (`7b 9e` magic + 64KiB フレーム + EOD) | [StreamFormat.md v1.4.1](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/StreamFormat.md) | ✅ | ✅ | |
| LZSA1 ブロック | [BlockFormat_LZSA1.md](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA1.md) | ✅ | ✅ | `encode` は LZSA1 ブロックを出力 |
| LZSA2 ブロック | [BlockFormat_LZSA2.md](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA2.md) | ✅ | ✅ | |
| dictionary モード (`-D`) | upstream CLI 用法 (StreamFormat.md 未記載) | ✅ | ✅ | `decode_with_prefix` / `decode_lzsa1_block_with_prefix` / `decode_lzsa2_block_with_prefix` で外部履歴を前置、encode は `encode_with_prefix` / `encode_lzsa2_with_prefix`。wire 形式は不変 |
| backward モード (`-b`) | upstream `lzsa.c` (`-r -b`) / `src/shrink_context.c` 動作解析 | ✅ | ✅ | raw ブロック限定 (upstream も `-r` との組合せ必須)。`decode_lzsa{1,2}_block_backwards{,_with_prefix}` / `encode_lzsa{1,2}_block_backwards{,_with_prefix}`。stream コンテナは対象外 |

## ストリーム構造

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | 先頭 3 バイトは `7b 9e` + traits byte (bits7-5 = version V、bits4-0 = reserved Z) | StreamFormat.md: header | ✅ | `lzsa1_stream_reference_vector` / `lzsa2_stream_reference_vector` (統合) |
| 2 | Z bits != 0 は拒否。V は 0 (LZSA1) / 1 (LZSA2) のみ、他は拒否 | StreamFormat.md: traits byte | ✅ | `rejects_bad_signature` |
| 3 | 各フレームは 3 バイトの圧縮ブロックサイズ DSZ (byte0-1 = bits0-15、byte2 bit0 = bit16) + DSZ バイトのブロックデータ | StreamFormat.md: frame | ✅ | `lzsa1_stream_reference_vector` (統合) |
| 4 | DSZ byte2 の bit7 は uncompressed frame フラグ。設定時、ブロックデータをそのまま出力にコピー | StreamFormat.md: uncompressed flag | ✅ | `decode_stream_uncompressed_frame` |
| 5 | DSZ byte2 の bits1-6 は reserved で非ゼロなら拒否 | StreamFormat.md | ✅ | `rejects_reserved_dsz_bits` (v1/v2 両経路) |
| 6 | DSZ == 0 の 3 バイトが EOD フレーム (ストリーム終端) | StreamFormat.md: EOD | ✅ | 全ストリームベクタで検証 |
| 7 | フレームは最大 64KiB に展開。マッチオフセットは先行フレームの出力を参照可能 (ブロック間履歴) | StreamFormat.md | ✅ | `multi_frame_roundtrip` (統合、90000B) |

## LZSA1 ブロック

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 8 | コマンド列。各コマンドは token `<O\|LLL\|MMMM>` → 拡張リテラル長 → リテラル列 → オフセット下位 → [オフセット上位] → 拡張マッチ長 | [BlockFormat_LZSA1.md](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA1.md) | ✅ | `decode_l1_hand_built` |
| 9 | L = 0-6 直接、7 で拡張 byte: 0-248 → 7+v、249 → u16le、250 → 256+byte | BlockFormat_LZSA1.md: extra literal length | ✅ | `lzsa1_stream_reference_vector` (統合: 45 リテラル) |
| 10 | O bit 0 で 1 バイトオフセット (上位は 0xff → 距離 1-256)、1 で 2 バイト (距離 最大 64KiB)。オフセットは負値格納で dist = 0x10000 - stored | BlockFormat_LZSA1.md: match offset | ✅ | `lzsa1_raw_block_reference_vector` (統合: dist 45) |
| 11 | M = 0-14 で len = M+3。15 で拡張 byte: 0-237 → 18+v、238 → u16le (最終長)、239 → 256+byte | BlockFormat_LZSA1.md: extra match length / 参照 expand_block_v1.c | ✅ | `lzsa1_raw_block_reference_vector` (統合: len 8955) |
| 12 | ストリームブロックの最終コマンドはリテラルのみを含む (マッチなし)。ブロック境界はフレーム DSZ で判別 | [BlockFormat_LZSA1.md](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA1.md) | ✅ | `lzsa1_stream_reference_vector` (統合) |
| 13 | raw ブロックの最終コマンドは EOD マーカー: M=15 + オフセットバイト + 拡張 byte 238 + u16 0。EOD 以降にデータが残る場合は拒否 | BlockFormat_LZSA1.md: EOD detection | ✅ | `decode_l1_eod_raw`、`lzsa1_raw_block_reference_vector` (統合) |
| 14 | len-0 の EOD 条件はストリームモードでもブロック終端として受理 | 参照 expand_block_v1.c (`nMatchLen==0` → break) | ✅ | デコーダ実装 |

## LZSA2 ブロック

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 15 | コマンド列。各コマンドは token `<XYZ\|LL\|MMM>` → 拡張リテラル長 → リテラル列 → オフセット (XYZ 形式) → 拡張マッチ長。min match = 2 | [BlockFormat_LZSA2.md](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA2.md) | ✅ | `lzsa2_stream_reference_vector` (統合) |
| 16 | ブロック全体で共有される nibble ストリーム: byte の hi nibble を先に返し lo nibble を保留、次の nibble 読み出しで返す。byte 読み出しは保留 nibble を消費しない | BlockFormat_LZSA2.md: Reading nibbles / 参照 shrink/expand 実装 (slot 書き戻し方式) | ✅ | `lzsa2_stream_reference_vector` (統合) |
| 17 | L = 0-2 直接、3 で拡張 nibble: 0-14 → 3+n、15 で byte: 238 → len 0、239 → u16le、その他 → 18+b | BlockFormat_LZSA2.md / 参照 expand_block_v2.c | ✅ | `lzsa2_stream_reference_vector` (統合: 32 リテラル) |
| 18 | オフセット形式: 00Z → 5bit (nibble+Zbit、dist 1-32)、01Z → 9bit (byte+Zbit、dist 1-512)、10Z → 13bit (nibble+Zbit+byte、dist 513-8704)、110 → 16bit、111 → rep-match (直前オフセット再利用) | BlockFormat_LZSA2.md: match offset | ✅ | `lzsa2_raw_block_reference_vector` (統合) |
| 19 | M = 0-6 で len = M+2。7 で拡張 nibble: 0-14 → 9+n、15 で byte: 232 → len 0 (EOD)、233 → u16le、その他 → 24+b | BlockFormat_LZSA2.md / 参照 expand_block_v2.c | ✅ | `decode_l2_eod_raw`、`lzsa2_raw_block_reference_vector` (統合: len 8955) |
| 20 | raw ブロックの最終コマンドは EOD: token の M=7 + 拡張 nibble 15 + byte 232 (オフセットは rep-match 等で読み飛ばし可) | BlockFormat_LZSA2.md: EOD detection / 参照 shrink_block_v2.c | ✅ | `decode_l2_eod_raw` |

## バリデーション / エラー処理

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 21 | magic 欠損・1-2 バイト入力・フレームヘッダ/ブロック切り詰めの拒否 | StreamFormat.md | ✅ | `rejects_bad_signature`、`rejects_truncated`。0 バイト入力は空出力を返す crate 慣例 (`empty_input`) |
| 22 | オフセット 0 または出力済みバイト数超過のマッチは拒否 | LZ77 規約 | ✅ | `rejects_truncated` / デコーダガード |
| 23 | `decode_bounded` で出力上限を強制 (圧縮ブロック・verbatim フレーム双方) | crate contract | ✅ | `decode_bounded_enforces_limit` (統合) |
| 24 | 拡張長フィールドのマーカー byte (LZSA1: 238/239/249/250、LZSA2: 232/233/238/239) の曖昧な扱いを参照実装の読みに一致させる | 参照 expand_block_v1.c / expand_block_v2.c | ✅ | `lzsa1_defensive_marker_bytes`, `lzsa2_defensive_marker_bytes` (手組みブロックで各分岐を固定) |

## エンコード範囲 / 既知の制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 25 | `encode` は LZSA1 ストリーム、`encode_lzsa2` は LZSA2 ストリームを出力 (traits byte の V で選択) | StreamFormat.md | ✅ | `encode_roundtrips_and_redecodes` (統合) |
| 26 | フレームは 64KiB 出力単位で分割。マッチは先行フレームの履歴を参照可能 | StreamFormat.md | ✅ | `multi_frame_roundtrip` (統合) |
| 27 | 圧縮ブロックが入力以上に膨らむ場合、または 1 コマンドのリテラル長上限 (65535) を超えるリテラルランが発生した場合、verbatim フレームにフォールバック | StreamFormat.md: uncompressed flag | ✅ | `verbatim_frame_for_incompressible` (DSZ byte2 bit7 を直接検証)、`literal_len_u16_max_boundary` (u16 リテラル長上限値 65535 の decode 境界) |
| 28 | ストリームブロックは必ずリテラルのみの最終コマンド (L=0 可) で閉じる。raw ブロックは EOD コマンドで閉じる | BlockFormat_LZSA1/2.md | ✅ | `lzsa_tool` 出力との比較 (ローカル検証) |
| 29 | LZSA2 エンコーダは距離に応じて 5bit (≤32) / 9bit (≤512) / 13bit (≤8704) / 16bit を選択し、直前距離と一致する場合は rep-match を出力 | [BlockFormat_LZSA2.md](https://raw.githubusercontent.com/emmanuel-marty/lzsa/1.4.1/BlockFormat_LZSA2.md) | ✅ | `roundtrip_various` (tier テスト) |
| 30 | エンコーダのマッチ探索は greedy 単一候補ハッシュ (LZSA1: 3B、LZSA2: 2B)。参照の optimal parse とのバイト一致は保証しない | 実装選択 | ✅ | roundtrip で検証 |

## その他

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 31 | CLI は `lzsa` (v1) / `lzsa2` (v2) フォーマットで compress、ストリームの `7b 9e` magic で自動検出、raw ブロックは CLI 非対応 (library API のみ) | crate CLI contract | ✅ | `detect_lzsa` (detect 分岐を実装済み)。backward は raw ブロック限定のため CLI からは提供しない (library API のみ) |
| 32 | backward モード (`-r -b`): 入力を `reverse` → 通常ブロックとして符号化 → 出力を `reverse` する pure byte-reversal wrapper で wire 形式は不変。decode は逆順に適用。prefix 履歴は ZX 系の suffix 履歴と異なり正順のまま | 参照 `lzsa.c` / `shrink_context.c` 解析 + upstream 生成ベクタで検証 | ✅ | `lzsa1_raw_block_backwards_reference_vector` / `lzsa2_raw_block_backwards_reference_vector` / `backwards_block_byte_reversal_property` (統合) |
| 33 | raw ブロック forward/backward encode (`encode_lzsa{1,2}_block{,_backwards}` 系) は `Option<Vec<u8>>` を返す。1 raw ブロックで表現不能な入力 (literal ラン上限超過等) では `None` — stream の verbatim フレーム fallback は利用不可 | BlockFormat_LZSA1/2.md | ✅ | `backwards_raw_block_roundtrip` (統合) |

## 出典 / 検証メモ

- 参照実装 `emmanuel-marty/lzsa` は zlib license (`src/matchfinder.c` のみ CC0)。本実装は `StreamFormat.md` / `BlockFormat_LZSA1.md` / `BlockFormat_LZSA2.md` から書かれた独立実装であり、コードの移植は行っていない。
- 統合テストの `TEXT_LZSA*` / `TEXT_RLZSA*` は参照 `lzsa` v1.4.1 (`-f1`/`-f2`、ストリームおよび `-r` raw) で生成した既知解答ベクタ (decode のみ検証)。
- ローカル検証として、本実装の `encode` / `encode_lzsa2` 出力を参照 `lzsa -d` で復号し一致を確認 (テキスト・混合・乱数入力)。非圧縮入力では verbatim フレームが選ばれることも一致確認。
- 仕様メモ: 拡張長フィールドの「特殊 byte」範囲は、仕様書にはエンコーダが出力する範囲のみ記載される。参照デコーダ (expand_block_v*.c) は byte 値を加算してオーバーフロー条件 (256/257) で分岐するため、仕様書未記載の byte 値 (LZSA1: 240-248,251-255 / LZSA2: 234-237,240-255 など) も非マーカー長として受理する。本実装は参照デコーダの挙動に合わせている。
- 仕様メモ: `BlockFormat_LZSA2.md` の EOD 節は「9-bit match offset (set to zero)」と記述するが、upstream v1.4.1 が実際に出力するのは XYZ=111 rep-match (offset byte なし) — 参照ベクタ `TEXT_RLZSA2` 末尾の `e7 f0 e8` が証拠。decoder は XYZ に応じてオフセットを読むため両形式を受理する。
- 仕様メモ: `StreamFormat.md` の traits byte 図は 7 桁 (`7 6 5 4 3 2 1`、bit0 欠落) で upstream 側の typo。実装は upstream `lzsa.c` と同様に Z = bits4-0 (5 bit) として解釈する。
- LZSA2 のオフセットは、仕様書では「負値格納 + 未使用ビット=1」のモデルで説明されるが、参照デコーダは `(stored ^ mask) + 1` で正の距離を直接得る。両モデルは等価であり、本実装は参照と同じ正距離モデルで書いている。
- `lzsa -b` (backward) モードは raw ブロック限定で `decode_lzsa{1,2}_block_backwards` / `encode_lzsa{1,2}_block_backwards` 系に対応済み (upstream と同様 `-r` 相当の raw ブロックのみで、stream コンテナは対象外)。`lzsa` 独自の小ブロックストリーム API は対象外 (StreamFormat.md 未記載)。辞書 (`-D`) は `decode_with_prefix` / `decode_lzsa*_block_with_prefix` / `encode_with_prefix` / `encode_lzsa2_with_prefix` で対応済み。

## 集計

| 状態 | 件数 |
|------|------|
| ✅ 実装+テスト済み  | 33 |
| **合計** | **33** |
