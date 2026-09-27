# Stac LZS (RFC 2395)

| 項目 | 内容 |
|------|------|
| 形式概要 | RFC 2395 "IP Payload Compression Using LZS"。LZ77 系の datagram 指向圧縮。2048 バイトのスライディングウィンドウを使い、datagram 毎に履歴をリセットする。§2.2 のトークン列文法は ANSI X3.241-1994 からの informational 転記 |
| 基準仕様 | [RFC 2395](https://www.rfc-editor.org/rfc/rfc2395) (ローカルスナップショット: `docs/spec/sources/rfc2395.txt`) |
| 実装 | `archive::compress::lzs` (encode / decode / decode_bounded)。pure-Rust 実装 |

## 対応バリアント・スコープ

| バリアント | 仕様根拠 | decode | encode | 備考 |
|---|---|---|---|---|
| RFC 2395 §2.2 compressed stream (token stream + end marker) | RFC 2395 §2.2 | ✅ | ✅ | 単一 datagram = 1 バイト列の one-shot API |
| IPComp ヘッダ (CPI)・IPCA ネゴシエーション (ISAKMP transform) | RFC 2395 §4 / RFC 3173 | ❌ | ❌ | intentional scope。圧縮ペイロード本体の codec のみ |
| PPP Stac LZS framing (RFC 1974 §3 以降) / LZS-DCP history mode (RFC 1967) | RFC 1974 / RFC 1967 | ❌ | ❌ | intentional scope。bitstream 文法は同一だが transport 層は対象外 |
| 非圧縮フォーム (IPComp ヘッダ省略で平文転送) | RFC 2395 §2.2 | — | — | codec の責任外。呼び出し側が圧縮効率を判断する |

## ビットストリーム (MSB-first)

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 1 | `<Compressed Stream> := [<Compressed String>] <End Marker>`。end marker 必須、欠落は拒否 | RFC 2395 §2.2 | ✅ | `missing_end_marker_is_error`、`empty_input_stream_is_error` |
| 2 | リテラル: `0` + 8bit raw byte | RFC 2395 §2.2 | ✅ | `literal_only`、fixture `lit`/`rand` |
| 3 | Copy token: `1` + `<Offset>` + `<Length>` | RFC 2395 §2.2 | ✅ | `hand_built_copy` |
| 4 | Short offset: `1` + 7bit (1..=127) | RFC 2395 §2.2 `<Offset>` | ✅ | `hand_built_copy`、fixture `repeat` |
| 5 | Long offset: `0` + 11bit (1..=2047) | RFC 2395 §2.2 `<Offset>` | ✅ | `long_offset_form`、fixture `window` |
| 6 | Short offset 値 0 (`110000000`) は end marker。以降の trailing bit/byte は全てパディングとして無視 | RFC 2395 §2.2 `<End Marker>` + §2.3 | ✅ | `empty_input_emits_only_end_marker`、`trailing_padding_bytes_ignored` |
| 7 | Long offset 値 0 は reserved → 拒否 | RFC 2395 §2.2 + crate 防御 | ✅ | `reserved_long_zero_offset` |
| 8 | Length: `00`=2, `01`=3, `10`=4, `1100`=5, `1101`=6, `1110`=7 | RFC 2395 §2.2 `<Length>` | ✅ | `length_table_boundaries` |
| 9 | Length ≥ 8: `1111` 開始後、`1111` nibble 毎に +15、最後の非 `1111` nibble で終了 (`1111 0000`=8 … `1111 1111 0000`=23 …) | RFC 2395 §2.2 `<Length>` | ✅ | `length_table_boundaries`、`long_match_length_chain` |
| 10 | パディング: 圧縮ペイロードはオクテット単位。end marker 後の残り bit はエンコーダが `1` で埋める | RFC 2395 §2.3 + ANSI 慣行 | ✅ | `empty_input_emits_only_end_marker` |
| 11 | Copy 参照は出力末尾から offset 分遡った位置から 1 バイトずつ複写 (オーバーラップ可) | RFC 2395 §2.2 + 参照実装 (compcol) の挙動 | ✅ | `overlapping_copy`、fixture `overlap`/`zeros` |

## 履歴 / ウィンドウ

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 12 | スライディングウィンドウ 2048 バイト。datagram 毎に履歴をリセットするため、デコーダの出力そのものが履歴 | RFC 2395 §1.2, §2.1, §3 | ✅ | `roundtrip_varied`、`window_span_roundtrip` (統合) |
| 13 | copy offset > 生成済み出力サイズは拒否 | RFC 2395 §2.2 + crate 防御 | ✅ | `offset_exceeds_history` |
| 14 | copy offset > 2047 (11bit 表現可能上限) は拒否 | RFC 2395 §2.2 `<Offset>` | ✅ | `window_distance_cap` |
| 15 | エンコーダのマッチ距離上限は 2047 (11bit long form の最大値)。距離 2048 は表現不能のため符号化しない | RFC 2395 §2.2 `<Offset>` | ✅ | `window_distance_cap` |

## マッチ長 / 防御的制約

| # | 要件 | 仕様参照 | 状態 | テスト名 / 備考 |
|---|------|----------|------|----------------|
| 16 | 最小マッチ長 2 (`00`) | RFC 2395 §2.2 `<Length>` | ✅ | `length_table_boundaries` |
| 17 | 最大マッチ長は文法上 unbounded だが、単一マッチ 16MiB 超は破損/攻撃入力として拒否 (crate 側の sanity cap) | crate 判定 | ✅ | `truncated_match_length_chain` |
| 18 | `decode_bounded` は `OutputLimitExceeded` で出力量を制限 | ✅ | `decode_bounded_limit` |
| 19 | トークン列の途中切れ (offset/length の読み込み不足、nibble chain 未終端) は拒否 | ✅ | `missing_end_marker_is_error`、`truncated_match_length_chain` |

## API / 単一ショット

| # | 要件 | 状態 | テスト名 / 備考 |
|---|------|------|----------------|
| 20 | `encode(input)` は end marker + `1` パディング付きの単一 compressed payload を返す。入力サイズ制限なし (window は 2048B で符号化される) | ✅ | `encode_decode_roundtrip` (統合) |
| 21 | `decode(input)` は入力全体を 1 compressed payload として end marker までデコード | ✅ | fixture decode テスト |
| 22 | 履歴は datagram 毎リセットのため stateful API は提供しない (RFC 2395 §3 の MUST reset に対応) | ✅ | API 設計で担保 |

## 相互運用 / テスト資産

| # | 内容 | 状態 |
|---|------|------|
| 23 | エンコード方向 interop: 本 crate エンコーダの出力を compcol (MIT, KarpelesLab) の LZS デコーダでデコードし 10 ケース全件一致 (empty/リテラルのみ/長マッチ/nibble chain/長距離 offset/ランダムデータ等) | ✅ (`.local/lzs_oracle/`) |
| 24 | デコード方向 interop: compcol エンコーダの出力を本 crate でデコードし全件一致 | ✅ (`.local/lzs_oracle/`) |
| 25 | fixture: `tests/fixtures/lzs/` に `*.lzs` + `*.expected` 10 組。全件本 crate エンコーダ生成 + compcol オラクル検証済み | ✅ |

## Intentional scope / 既知制約

- IPComp ヘッダ (4 バイト: nexthdr/flags/CPI)、ISAKMP/IPCA ネゴシエーション、compressibility test (§4.5) は transport 層として対象外。
- RFC 1974 (PPP Stac LZS) の packet framing・RFC 1967 (LZS-DCP) の history 維持モードは対象外 (bitstream 文法は同一だが transport が異なる)。
- RFC 2395 の「非圧縮フォーム」(IPComp ヘッダ省略の平文転送) は codec 外の判断。本 crate の `encode` は常に compressed form を出力する。
- エンコーダは greedy 単一ハッシュ (2 バイトキー) のベースライン品質 (圧縮率最適化は意図しない)。
- `decode` は end marker を必須とする (RFC 2395 §2.3: end marker がパディングとの曖昧性を解消する)。end marker 欠落はエラー。

## 特許ステータス (Patent Status)

RFC 2395 §1.3 は Hi/fn, Inc. が LZS アルゴリズムの特許を保有していた旨、および IPPCP/IPSec/TLS/PPP 用途に無償ライセンスを提供していた旨を記載する。これは MPPC (RFC 2118 §1.1) のような使用禁止型の field-of-use 条項ではなく、特許ロイヤルティに関する記述である。

監査時の独立調査により、対象特許ファミリ (US 4,701,745 / 5,016,009 / 5,126,739 / 5,146,221 / 5,463,390 等、1985-1993 年出願) はすべて失効していることを確認した。US 5,126,739 は Google Patents 上で "Expired - Fee Related" (想定失効日 2009-06-30) と記載され、Hi/fn の LZS 特許群は維持費不払いにより失効し、2007 年の復活申請も失敗したと報告されている (Wikipedia "Lempel–Ziv–Stac" 記事)。2016 年以降、MIT ライセンスの独立実装 (例: `cmcqueen/lzs-compression`, `KarpelesLab/compcol`) が特許言及なしに公開されている実務的実態もこれを裏付ける。

本モジュールは一般用途の archive/compression ライブラリの codec として実装するものであり、IPPCP/IPSec/TLS/PPP プロトコルの実装ではない。これは透明性のための記録であり、法的助言ではない。網羅的な特許調査 (freedom-to-operate opinion) は実施していない。

## Provenance

- 一次仕様: RFC 2395 §2.2 の文法定義 (ANSI X3.241-1994 からの informational 転記部分) のみを使用。ANSI X3.241 本体 (有償規格文書) は未入手・未参照。
- 参照実装: `KarpelesLab/compcol` v0.6.11 (MIT) の LZS codec を挙動確認用オラクルとして `.local/` にローカルビルドし、双方向の encode/decode で wire format の一致を検証。コードのコピーなし。
- fixture は全件本 crate エンコーダで生成し、compcol オラクルでデコード検証済み。
